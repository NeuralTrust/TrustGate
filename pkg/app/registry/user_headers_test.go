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

package registry_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appmocks "github.com/NeuralTrust/TrustGate/pkg/app/registry/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// prefixVault is an in-memory vault with the admin prefix operations and a
// replicated write, recording which path a write took.
type prefixVault struct {
	mu         sync.Mutex
	creds      map[string]*vaultdomain.Credential
	replicated int
}

func newPrefixVault() *prefixVault { return &prefixVault{creds: map[string]*vaultdomain.Credential{}} }

func vkey(gw ids.GatewayID, sub, provider string) string {
	return gw.String() + "\x00" + sub + "\x00" + provider
}

func (v *prefixVault) Upsert(_ context.Context, c *vaultdomain.Credential) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	cp := *c
	cp.UpdatedAt = time.Now()
	v.creds[vkey(c.GatewayID, c.PrincipalSub, c.Provider)] = &cp
	return nil
}

func (v *prefixVault) UpsertReplicated(ctx context.Context, c *vaultdomain.Credential) error {
	v.replicated++
	return v.Upsert(ctx, c)
}

func (v *prefixVault) Find(_ context.Context, gw ids.GatewayID, sub, provider string) (*vaultdomain.Credential, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	c, ok := v.creds[vkey(gw, sub, provider)]
	if !ok {
		return nil, vaultdomain.ErrNotFound
	}
	return c, nil
}

func (v *prefixVault) ListByPrincipal(context.Context, ids.GatewayID, string) ([]*vaultdomain.Credential, error) {
	return nil, nil
}

func (v *prefixVault) Delete(_ context.Context, gw ids.GatewayID, sub, provider string) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	k := vkey(gw, sub, provider)
	if _, ok := v.creds[k]; !ok {
		return vaultdomain.ErrNotFound
	}
	delete(v.creds, k)
	return nil
}

func (v *prefixVault) ListByProviderPrefix(_ context.Context, gw ids.GatewayID, prefix string) ([]vaultdomain.CredentialSummary, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	var out []vaultdomain.CredentialSummary
	for _, c := range v.creds {
		if c.GatewayID == gw && strings.HasPrefix(c.Provider, prefix) {
			out = append(out, vaultdomain.CredentialSummary{
				PrincipalSub: c.PrincipalSub, Provider: c.Provider, ExpiresAt: c.ExpiresAt, UpdatedAt: c.UpdatedAt,
			})
		}
	}
	return out, nil
}

func (v *prefixVault) DeleteByProviderPrefix(_ context.Context, gw ids.GatewayID, prefix string) (int, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	n := 0
	for k, c := range v.creds {
		if c.GatewayID == gw && strings.HasPrefix(c.Provider, prefix) {
			delete(v.creds, k)
			n++
		}
	}
	return n, nil
}

func keyedRegistry(t *testing.T, gw ids.GatewayID) *domain.Registry {
	t.Helper()
	reg, err := domain.NewMCPRegistry(gw, "keyed", "", &domain.MCPTarget{
		URL:  "https://keyed.example.com/mcp",
		Auth: &domain.MCPAuth{Mode: domain.MCPAuthModeNone},
		UserHeaders: []domain.MCPUserHeader{
			{Name: "X-API-Key", Required: true, Secret: true},
			{Name: "X-Account"},
		},
	})
	require.NoError(t, err)
	return reg
}

func TestUserHeaderAdmin_ImportListReset(t *testing.T) {
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	reg := keyedRegistry(t, gw)
	finder := appmocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil)
	vault := newPrefixVault()
	admin := appregistry.NewUserHeaderAdmin(finder, vault, &ticketRecorder{}, nil)

	n, err := admin.Import(ctx, gw, reg.ID, []appregistry.UserHeaderImportRow{
		{PrincipalSub: "ana", Header: "x-api-key", Value: "ana-key"},
		{PrincipalSub: "app:c1:bruno", Header: "X-API-Key", Value: "bruno-key"},
		{PrincipalSub: "bruno-oauth", Header: "X-Account", Value: "acct"},
	})
	require.NoError(t, err)
	require.Equal(t, 3, n)
	require.Equal(t, 3, vault.replicated, "admin writes must reach the data plane's store")

	holders, err := admin.Holders(ctx, gw, reg.ID)
	require.NoError(t, err)
	require.Len(t, holders, 3)
	require.Equal(t, "ana", holders[0].PrincipalSub)
	require.Empty(t, holders[0].Missing)
	require.Equal(t, "bruno-oauth", holders[2].PrincipalSub)
	require.Equal(t, []string{"X-API-Key"}, holders[2].Missing)

	removed, err := admin.Reset(ctx, gw, reg.ID, "ana")
	require.NoError(t, err)
	require.Equal(t, 1, removed)
	removed, err = admin.Reset(ctx, gw, reg.ID, "")
	require.NoError(t, err)
	require.Equal(t, 2, removed)
	holders, err = admin.Holders(ctx, gw, reg.ID)
	require.NoError(t, err)
	require.Empty(t, holders)
}

func TestUserHeaderAdmin_ImportRefusesBadRowsBeforeWriting(t *testing.T) {
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	reg := keyedRegistry(t, gw)
	finder := appmocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil)
	cases := map[string][]appregistry.UserHeaderImportRow{
		"unknown header":     {{PrincipalSub: "ana", Header: "X-API-Key", Value: "ok"}, {PrincipalSub: "ana", Header: "X-Nope", Value: "v"}},
		"crlf":               {{PrincipalSub: "ana", Header: "X-API-Key", Value: "v\r\nX: 1"}},
		"application itself": {{PrincipalSub: "app:c1", Header: "X-API-Key", Value: "v"}},
		"instance subject":   {{PrincipalSub: "instance:" + reg.ID.String(), Header: "X-API-Key", Value: "v"}},
		"duplicate":          {{PrincipalSub: "ana", Header: "X-API-Key", Value: "a"}, {PrincipalSub: "ana", Header: "x-api-key", Value: "b"}},
		"empty":              {},
	}
	for name, rows := range cases {
		t.Run(name, func(t *testing.T) {
			vault := newPrefixVault()
			admin := appregistry.NewUserHeaderAdmin(finder, vault, &ticketRecorder{}, nil)
			_, err := admin.Import(ctx, gw, reg.ID, rows)
			require.ErrorIs(t, err, commonerrors.ErrValidation)
			require.NotContains(t, err.Error(), "X: 1", "the error must not echo a value")
			require.Empty(t, vault.creds, "nothing is written when one row is refused")
		})
	}
}

func TestUserHeaderAdmin_LinkActsAsThePerson(t *testing.T) {
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	reg := keyedRegistry(t, gw)
	finder := appmocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil)
	tickets := &ticketRecorder{}
	admin := appregistry.NewUserHeaderAdmin(finder, newPrefixVault(), tickets, nil)

	link, err := admin.Link(ctx, gw, reg.ID, "ana", "/dev/mcp", "")
	require.NoError(t, err)
	require.Equal(t, "tk", link.Ticket)
	require.Equal(t, "ana", tickets.last.principalSub)
	require.Equal(t, reg.ID.String(), tickets.last.instanceID)
	require.Equal(t, "/dev/mcp", tickets.last.consumerPath)

	_, err = admin.Link(ctx, gw, reg.ID, "app:c1", "", "")
	require.ErrorIs(t, err, commonerrors.ErrValidation)
}

func TestUserHeaderAdmin_RegistryWithoutUserHeaders(t *testing.T) {
	ctx := context.Background()
	gw := ids.New[ids.GatewayKind]()
	reg, err := domain.NewMCPRegistry(gw, "plain", "", &domain.MCPTarget{URL: "https://p.example.com/mcp"})
	require.NoError(t, err)
	finder := appmocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gw, reg.ID).Return(reg, nil)
	admin := appregistry.NewUserHeaderAdmin(finder, newPrefixVault(), &ticketRecorder{}, nil)
	_, err = admin.Holders(ctx, gw, reg.ID)
	require.ErrorIs(t, err, commonerrors.ErrConflict)
}
