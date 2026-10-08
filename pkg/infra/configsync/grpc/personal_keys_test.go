// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package grpc

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// memIssuer holds one key per (gateway, owner), as the control plane does.
type memIssuer struct {
	keys   map[string]*appauth.PersonalKey
	err    error
	groups []string
	email  string
}

func newMemIssuer() *memIssuer { return &memIssuer{keys: map[string]*appauth.PersonalKey{}} }

func ownerKey(gw ids.GatewayID, owner string) string { return gw.String() + "|" + owner }

func (m *memIssuer) Get(_ context.Context, gw ids.GatewayID, owner string) (*appauth.PersonalKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	k, ok := m.keys[ownerKey(gw, owner)]
	if !ok {
		return nil, authdomain.ErrNotFound
	}
	copied := *k.Auth
	copied.RawKey = ""
	return &appauth.PersonalKey{Auth: &copied, ConsumerIDs: k.ConsumerIDs}, nil
}

func (m *memIssuer) Create(_ context.Context, gw ids.GatewayID, owner appauth.PersonalKeyOwner, groups []string) (*appauth.PersonalKey, error) {
	if m.err != nil {
		return nil, m.err
	}
	if _, ok := m.keys[ownerKey(gw, owner.ID)]; ok {
		return nil, authdomain.ErrOwnedKeyExists
	}
	m.groups = groups
	m.email = owner.Email
	expires := time.Now().Add(time.Hour).Truncate(time.Second)
	a, err := authdomain.NewOwnedAPIKeyAuth(gw, owner.ID, expires, time.Now())
	if err != nil {
		return nil, err
	}
	a.OwnerGroups = groups
	a.OwnerEmail = owner.Email
	key := &appauth.PersonalKey{Auth: a, ConsumerIDs: []ids.ConsumerID{ids.New[ids.ConsumerKind]()}}
	m.keys[ownerKey(gw, owner.ID)] = key
	return key, nil
}

func (m *memIssuer) Rotate(ctx context.Context, gw ids.GatewayID, owner string) (*appauth.PersonalKey, error) {
	k, err := m.Get(ctx, gw, owner)
	if err != nil {
		return nil, err
	}
	k.Auth.RawKey = "ag_rotated"
	return k, nil
}

func (m *memIssuer) Revoke(_ context.Context, gw ids.GatewayID, owner string) error {
	if _, ok := m.keys[ownerKey(gw, owner)]; !ok {
		return authdomain.ErrNotFound
	}
	delete(m.keys, ownerKey(gw, owner))
	return nil
}

func dialPersonalKeys(t *testing.T, issuer appauth.PersonalKeyIssuer) *PersonalKeysClient {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer()
	RegisterPersonalKeys(NewPersonalKeysService(issuer, nil, discardLogger()))(gsrv)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return NewPersonalKeysClient(conn)
}

// The data plane's page reaches the control plane's key: created with the
// owner's email and groups, its secret back once, then read without it, rotated, and
// revoked, every refusal arriving as the error the console's routes answer.
func TestPersonalKeysClient_RoundTrip(t *testing.T) {
	issuer := newMemIssuer()
	client := dialPersonalKeys(t, issuer)
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()

	if _, err := client.Get(ctx, gw, "alice"); !errors.Is(err, authdomain.ErrNotFound) {
		t.Fatalf("Get before create: err = %v, want ErrNotFound", err)
	}
	created, err := client.Create(ctx, gw, appauth.PersonalKeyOwner{ID: "alice", Email: "alice@acme.test"}, []string{"eng"})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Auth.RawKey == "" || created.Auth.RawKey != issuer.keys[ownerKey(gw, "alice")].Auth.RawKey {
		t.Fatal("Create must return the secret the control plane minted")
	}
	if created.Auth.OwnerID != "alice" || created.Auth.ExpiresAt == nil || len(created.ConsumerIDs) != 1 {
		t.Fatalf("created = %+v, want the owner, the expiry and the links", created.Auth)
	}
	if len(issuer.groups) != 1 || issuer.groups[0] != "eng" {
		t.Fatalf("groups = %v, want the owner's", issuer.groups)
	}
	if issuer.email != "alice@acme.test" || created.Auth.OwnerEmail != "alice@acme.test" {
		t.Fatalf("email = %q, created = %q, want the owner's both ways", issuer.email, created.Auth.OwnerEmail)
	}

	if _, err := client.Create(ctx, gw, appauth.PersonalKeyOwner{ID: "alice"}, nil); !errors.Is(err, authdomain.ErrOwnedKeyExists) {
		t.Fatalf("second Create: err = %v, want ErrOwnedKeyExists", err)
	}
	got, err := client.Get(ctx, gw, "alice")
	if err != nil || got.Auth.RawKey != "" || got.Auth.KeyPrefix == "" {
		t.Fatalf("Get: %+v / %v, want the key without its secret", got, err)
	}
	rotated, err := client.Rotate(ctx, gw, "alice")
	if err != nil || rotated.Auth.RawKey != "ag_rotated" {
		t.Fatalf("Rotate: %+v / %v, want the new secret", rotated, err)
	}
	if err := client.Revoke(ctx, gw, "alice"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := client.Revoke(ctx, gw, "alice"); !errors.Is(err, authdomain.ErrNotFound) {
		t.Fatalf("second Revoke: err = %v, want ErrNotFound", err)
	}

	issuer.err = consumerdomain.ErrHybridPersonal
	if _, err := client.Create(ctx, gw, appauth.PersonalKeyOwner{ID: "bob"}, nil); !errors.Is(err, consumerdomain.ErrHybridPersonal) {
		t.Fatalf("Create on a hybrid gateway: err = %v, want ErrHybridPersonal", err)
	}
}

// A data plane reaches only the gateways its config-sync scope covers.
func TestPersonalKeysService_RefusesAGatewayOutsideTheCallersScope(t *testing.T) {
	acme := tenantGateway(t, "acme")
	globex := tenantGateway(t, "globex")
	issuer := newMemIssuer()
	svc := NewPersonalKeysService(issuer, &fakeGateways{
		byID: map[ids.GatewayID]*gatewaydomain.Gateway{acme.ID: acme, globex.ID: globex},
	}, discardLogger())
	scoped := WithScope(context.Background(), acme.ID.String())

	if _, err := svc.Create(scoped, &snapshotpb.CreatePersonalKeyRequest{GatewayId: globex.ID.String(), OwnerId: "mallory"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Create on another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if _, err := svc.Get(scoped, &snapshotpb.PersonalKeyRequest{GatewayId: globex.ID.String(), OwnerId: "victim"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("Get on another tenant's gateway: code = %v, want PermissionDenied", status.Code(err))
	}
	if len(issuer.keys) != 0 {
		t.Fatal("nothing may be written for a gateway outside the scope")
	}
	if _, err := svc.Create(scoped, &snapshotpb.CreatePersonalKeyRequest{GatewayId: acme.ID.String(), OwnerId: "alice"}); err != nil {
		t.Fatalf("Create on the caller's own gateway: %v", err)
	}
}
