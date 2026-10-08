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
	"fmt"
	"log/slog"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PersonalKeysService serves the MCP Store's personal key page on the control
// plane. The data plane has established who the owner is; this side checks the
// gateway against the caller's config-sync scope and leaves every other rule to
// the issuer, the same one the console's routes reach.
type PersonalKeysService struct {
	snapshotpb.UnimplementedPersonalKeysServer
	issuer   appauth.PersonalKeyIssuer
	gateways GatewayResolver
	logger   *slog.Logger
}

// NewPersonalKeysService returns the control-plane side of the channel.
func NewPersonalKeysService(issuer appauth.PersonalKeyIssuer, gateways GatewayResolver, logger *slog.Logger) *PersonalKeysService {
	if logger == nil {
		logger = slog.Default()
	}
	return &PersonalKeysService{issuer: issuer, gateways: gateways, logger: logger}
}

// RegisterPersonalKeys returns the registration of the PersonalKeys channel.
func RegisterPersonalKeys(srv snapshotpb.PersonalKeysServer) ServiceRegistration {
	return func(r grpc.ServiceRegistrar) { snapshotpb.RegisterPersonalKeysServer(r, srv) }
}

func (s *PersonalKeysService) Get(ctx context.Context, req *snapshotpb.PersonalKeyRequest) (*snapshotpb.PersonalKeyResponse, error) {
	gatewayID, err := s.authorize(ctx, "get", req.GetGatewayId())
	if err != nil {
		return nil, err
	}
	key, err := s.issuer.Get(ctx, gatewayID, req.GetOwnerId())
	if err != nil {
		return nil, personalKeyStatus("get", err)
	}
	return &snapshotpb.PersonalKeyResponse{Key: personalKeyToProto(key, false)}, nil
}

func (s *PersonalKeysService) Create(ctx context.Context, req *snapshotpb.CreatePersonalKeyRequest) (*snapshotpb.PersonalKeyResponse, error) {
	gatewayID, err := s.authorize(ctx, "create", req.GetGatewayId())
	if err != nil {
		return nil, err
	}
	key, err := s.issuer.Create(ctx, gatewayID, req.GetOwnerId(), req.GetGroups())
	if err != nil {
		return nil, personalKeyStatus("create", err)
	}
	return &snapshotpb.PersonalKeyResponse{Key: personalKeyToProto(key, true)}, nil
}

func (s *PersonalKeysService) Rotate(ctx context.Context, req *snapshotpb.PersonalKeyRequest) (*snapshotpb.PersonalKeyResponse, error) {
	gatewayID, err := s.authorize(ctx, "rotate", req.GetGatewayId())
	if err != nil {
		return nil, err
	}
	key, err := s.issuer.Rotate(ctx, gatewayID, req.GetOwnerId())
	if err != nil {
		return nil, personalKeyStatus("rotate", err)
	}
	return &snapshotpb.PersonalKeyResponse{Key: personalKeyToProto(key, true)}, nil
}

func (s *PersonalKeysService) Revoke(ctx context.Context, req *snapshotpb.PersonalKeyRequest) (*snapshotpb.RevokePersonalKeyResponse, error) {
	gatewayID, err := s.authorize(ctx, "revoke", req.GetGatewayId())
	if err != nil {
		return nil, err
	}
	if err := s.issuer.Revoke(ctx, gatewayID, req.GetOwnerId()); err != nil {
		return nil, personalKeyStatus("revoke", err)
	}
	return &snapshotpb.RevokePersonalKeyResponse{}, nil
}

func (s *PersonalKeysService) authorize(ctx context.Context, op, raw string) (ids.GatewayID, error) {
	gatewayID, err := ids.Parse[ids.GatewayKind](raw)
	if err != nil {
		return ids.GatewayID{}, status.Errorf(codes.InvalidArgument, "personal keys: %s: invalid gateway id", op)
	}
	if err := authorizeGatewayScope(ctx, s.gateways, s.logger, "personal keys", op, gatewayID); err != nil {
		return ids.GatewayID{}, err
	}
	return gatewayID, nil
}

// personalKeyStatus says what went wrong in a code the client turns back into
// the domain error, so the page answers as the console's routes do.
func personalKeyStatus(op string, err error) error {
	switch {
	case errors.Is(err, authdomain.ErrNotFound):
		return status.Errorf(codes.NotFound, "personal keys: %s: no personal key", op)
	case errors.Is(err, authdomain.ErrOwnedKeyExists):
		return status.Errorf(codes.AlreadyExists, "personal keys: %s: %v", op, authdomain.ErrOwnedKeyExists)
	case errors.Is(err, consumerdomain.ErrHybridPersonal):
		return status.Errorf(codes.FailedPrecondition, "personal keys: %s: %v", op, consumerdomain.ErrHybridPersonal)
	case errors.Is(err, authdomain.ErrOwnedExpiry), errors.Is(err, authdomain.ErrInvalidOwner):
		return status.Errorf(codes.InvalidArgument, "personal keys: %s: %v", op, err)
	default:
		return status.Errorf(codes.Internal, "personal keys: %s: %v", op, err)
	}
}

func personalKeyToProto(key *appauth.PersonalKey, withSecret bool) *snapshotpb.PersonalKey {
	if key == nil || key.Auth == nil {
		return nil
	}
	a := key.Auth
	out := &snapshotpb.PersonalKey{
		Id:            a.ID.String(),
		KeyPrefix:     a.KeyPrefix,
		KeySuffix:     a.KeySuffix,
		Enabled:       a.Enabled,
		CreatedAtUnix: a.CreatedAt.Unix(),
		OwnerGroups:   append([]string(nil), a.OwnerGroups...),
	}
	if a.ExpiresAt != nil {
		out.ExpiresAtUnix = a.ExpiresAt.Unix()
	}
	for _, id := range key.ConsumerIDs {
		out.ConsumerIds = append(out.ConsumerIds, id.String())
	}
	if withSecret {
		out.Secret = a.RawKey
	}
	return out
}

// PersonalKeysClient is the data plane's PersonalKeyIssuer: every call is
// made by the control plane, which owns the database.
type PersonalKeysClient struct {
	cli snapshotpb.PersonalKeysClient
}

var _ appauth.PersonalKeyIssuer = (*PersonalKeysClient)(nil)

// NewPersonalKeysClient returns the issuer over the config-sync connection.
func NewPersonalKeysClient(conn *grpc.ClientConn) *PersonalKeysClient {
	return &PersonalKeysClient{cli: snapshotpb.NewPersonalKeysClient(conn)}
}

func (c *PersonalKeysClient) Get(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*appauth.PersonalKey, error) {
	res, err := c.cli.Get(ctx, &snapshotpb.PersonalKeyRequest{GatewayId: gatewayID.String(), OwnerId: ownerID})
	if err != nil {
		return nil, personalKeyError("get", err)
	}
	return personalKeyFromProto(gatewayID, ownerID, res.GetKey())
}

func (c *PersonalKeysClient) Create(ctx context.Context, gatewayID ids.GatewayID, ownerID string, groups []string) (*appauth.PersonalKey, error) {
	res, err := c.cli.Create(ctx, &snapshotpb.CreatePersonalKeyRequest{GatewayId: gatewayID.String(), OwnerId: ownerID, Groups: groups})
	if err != nil {
		return nil, personalKeyError("create", err)
	}
	return personalKeyFromProto(gatewayID, ownerID, res.GetKey())
}

func (c *PersonalKeysClient) Rotate(ctx context.Context, gatewayID ids.GatewayID, ownerID string) (*appauth.PersonalKey, error) {
	res, err := c.cli.Rotate(ctx, &snapshotpb.PersonalKeyRequest{GatewayId: gatewayID.String(), OwnerId: ownerID})
	if err != nil {
		return nil, personalKeyError("rotate", err)
	}
	return personalKeyFromProto(gatewayID, ownerID, res.GetKey())
}

func (c *PersonalKeysClient) Revoke(ctx context.Context, gatewayID ids.GatewayID, ownerID string) error {
	if _, err := c.cli.Revoke(ctx, &snapshotpb.PersonalKeyRequest{GatewayId: gatewayID.String(), OwnerId: ownerID}); err != nil {
		return personalKeyError("revoke", err)
	}
	return nil
}

// personalKeyError turns a status back into the domain error it stood for.
func personalKeyError(op string, err error) error {
	switch status.Code(err) {
	case codes.NotFound:
		return authdomain.ErrNotFound
	case codes.AlreadyExists:
		return authdomain.ErrOwnedKeyExists
	case codes.FailedPrecondition:
		return consumerdomain.ErrHybridPersonal
	case codes.InvalidArgument:
		return fmt.Errorf("personal keys: %s: %w: %s", op, commonerrors.ErrValidation, status.Convert(err).Message())
	default:
		return fmt.Errorf("personal keys: %s: %w", op, err)
	}
}

func personalKeyFromProto(gatewayID ids.GatewayID, ownerID string, wire *snapshotpb.PersonalKey) (*appauth.PersonalKey, error) {
	if wire == nil {
		return nil, errors.New("personal keys: the control plane returned no key")
	}
	id, err := ids.Parse[ids.AuthKind](wire.GetId())
	if err != nil {
		return nil, fmt.Errorf("personal keys: bad key id: %w", err)
	}
	a := &authdomain.Auth{
		ID:          id,
		GatewayID:   gatewayID,
		OwnerID:     ownerID,
		KeyPrefix:   wire.GetKeyPrefix(),
		KeySuffix:   wire.GetKeySuffix(),
		Enabled:     wire.GetEnabled(),
		CreatedAt:   time.Unix(wire.GetCreatedAtUnix(), 0).UTC(),
		OwnerGroups: wire.GetOwnerGroups(),
		RawKey:      wire.GetSecret(),
	}
	if at := wire.GetExpiresAtUnix(); at != 0 {
		expires := time.Unix(at, 0).UTC()
		a.ExpiresAt = &expires
	}
	key := &appauth.PersonalKey{Auth: a, ConsumerIDs: []ids.ConsumerID{}}
	for _, raw := range wire.GetConsumerIds() {
		if cid, err := ids.Parse[ids.ConsumerKind](raw); err == nil {
			key.ConsumerIDs = append(key.ConsumerIDs, cid)
		}
	}
	return key, nil
}
