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
	"log/slog"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RegistryEnsurer materialises the shared registry for a catalog code on the
// control plane. It is defined here (rather than imported from the app layer) so
// this infra package depends only on the domain; the app-layer ensurer satisfies
// it structurally. May be nil, in which case EnsureRegistry reports Unimplemented.
type RegistryEnsurer interface {
	Ensure(ctx context.Context, gatewayID ids.GatewayID, code string) error
}

// GatewayResolver is the slice of the gateway repository the tenant check needs:
// resolving the gateway a request names so its tenant can be compared with the
// caller's config-sync scope. The full gatewaydomain.Repository satisfies it.
type GatewayResolver interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

// InstallationsService is the control-plane end of the StoreInstallations
// channel: it persists the Store's durable state on behalf of the DB-less data
// plane — the per-principal install rows (through the same installation
// repository the admin plane writes through) and, for self-service, the shared
// registry materialised from the catalog (through the ensurer). The data plane
// computes the install decision (catalog + registry governance) locally; only
// the writes it cannot make itself cross to here.
//
// Every RPC honours the caller's config-sync scope exactly as the snapshot RPCs
// do: a scoped data plane (a per-instance JWT) may only read and write
// installations of the gateway it is scoped to — or of a gateway in the tenant
// it is scoped to — and never those of another tenant, whatever gateway_id it
// puts on the wire. An unscoped caller (the shared-token deployment) sees every
// gateway, as its snapshot does.
type InstallationsService struct {
	snapshotpb.UnimplementedStoreInstallationsServer
	repo     installationdomain.Repository
	ensurer  RegistryEnsurer
	gateways GatewayResolver
	logger   *slog.Logger
}

// NewInstallationsService builds the StoreInstallations server over the live
// installation repository, the registry ensurer and the gateway resolver used
// for the tenant check. ensurer may be nil (a deployment without self-service
// materialisation), in which case EnsureRegistry reports Unimplemented rather
// than materialising a registry. gateways may be nil only in tests: without it a
// scoped caller is limited to the single gateway its scope names.
func NewInstallationsService(
	repo installationdomain.Repository,
	ensurer RegistryEnsurer,
	gateways GatewayResolver,
	logger *slog.Logger,
) *InstallationsService {
	if logger == nil {
		logger = slog.Default()
	}
	return &InstallationsService{repo: repo, ensurer: ensurer, gateways: gateways, logger: logger}
}

// Upsert persists one installation record minted by the data plane.
func (s *InstallationsService) Upsert(
	ctx context.Context,
	req *snapshotpb.UpsertInstallationRequest,
) (*snapshotpb.UpsertInstallationResponse, error) {
	if _, err := s.upsertInstallation(ctx, req); err != nil {
		return nil, err
	}
	return &snapshotpb.UpsertInstallationResponse{}, nil
}

func (s *InstallationsService) UpsertCanonical(
	ctx context.Context,
	req *snapshotpb.UpsertInstallationRequest,
) (*snapshotpb.FindInstallationResponse, error) {
	in, err := s.upsertInstallation(ctx, req)
	if err != nil {
		return nil, err
	}
	return &snapshotpb.FindInstallationResponse{Found: true, Installation: installationToProto(in)}, nil
}

func (s *InstallationsService) upsertInstallation(
	ctx context.Context,
	req *snapshotpb.UpsertInstallationRequest,
) (*installationdomain.Installation, error) {
	in, err := installationFromProto(req.GetInstallation())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "store installations: upsert: %v", err)
	}
	if err := s.authorizeGateway(ctx, "upsert", in.GatewayID); err != nil {
		return nil, err
	}
	if err := validateDataPlaneInstallation(in); err != nil {
		return nil, err
	}
	if err := s.repo.Upsert(ctx, in); err != nil {
		return nil, status.Errorf(codes.Internal, "store installations: upsert: %v", err)
	}
	return in, nil
}

// Find returns the installation for (gateway, principal, code), reporting a
// missing row as found=false rather than an error.
func (s *InstallationsService) Find(
	ctx context.Context,
	req *snapshotpb.FindInstallationRequest,
) (*snapshotpb.FindInstallationResponse, error) {
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "find")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeGateway(ctx, "find", gatewayID); err != nil {
		return nil, err
	}
	found, err := s.repo.Find(ctx, gatewayID, req.GetPrincipalSub(), req.GetCatalogCode())
	if err != nil {
		if errors.Is(err, installationdomain.ErrNotFound) {
			return &snapshotpb.FindInstallationResponse{Found: false}, nil
		}
		return nil, status.Errorf(codes.Internal, "store installations: find: %v", err)
	}
	return &snapshotpb.FindInstallationResponse{Found: true, Installation: installationToProto(found)}, nil
}

// ListByPrincipal returns everything a principal has installed on a gateway.
func (s *InstallationsService) ListByPrincipal(
	ctx context.Context,
	req *snapshotpb.ListByPrincipalRequest,
) (*snapshotpb.ListInstallationsResponse, error) {
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "list")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeGateway(ctx, "list", gatewayID); err != nil {
		return nil, err
	}
	items, err := s.repo.ListByPrincipal(ctx, gatewayID, req.GetPrincipalSub())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store installations: list: %v", err)
	}
	out := make([]*snapshotpb.Installation, 0, len(items))
	for _, in := range items {
		out = append(out, installationToProto(in))
	}
	return &snapshotpb.ListInstallationsResponse{Installations: out}, nil
}

func (s *InstallationsService) FindByID(
	ctx context.Context,
	req *snapshotpb.Installation,
) (*snapshotpb.FindInstallationResponse, error) {
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "find by id")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeGateway(ctx, "find by id", gatewayID); err != nil {
		return nil, err
	}
	id, err := parseInstallationID(req.GetId(), "find by id")
	if err != nil {
		return nil, err
	}
	found, err := s.repo.FindByID(ctx, gatewayID, req.GetPrincipalSub(), id)
	if errors.Is(err, installationdomain.ErrNotFound) {
		return &snapshotpb.FindInstallationResponse{Found: false}, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store installations: find by id: %v", err)
	}
	return &snapshotpb.FindInstallationResponse{Found: true, Installation: installationToProto(found)}, nil
}

func (s *InstallationsService) ListByPrincipalAndCode(
	ctx context.Context,
	req *snapshotpb.FindInstallationRequest,
) (*snapshotpb.ListInstallationsResponse, error) {
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "list by principal and code")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeGateway(ctx, "list by principal and code", gatewayID); err != nil {
		return nil, err
	}
	items, err := s.repo.ListByPrincipalAndCode(ctx, gatewayID, req.GetPrincipalSub(), req.GetCatalogCode())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store installations: list by principal and code: %v", err)
	}
	return installationListResponse(items), nil
}

func (s *InstallationsService) ListByCatalogCode(
	ctx context.Context,
	req *snapshotpb.FindInstallationRequest,
) (*snapshotpb.ListInstallationsResponse, error) {
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "list by catalog code")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeGateway(ctx, "list by catalog code", gatewayID); err != nil {
		return nil, err
	}
	items, err := s.repo.ListByCatalogCode(ctx, gatewayID, req.GetCatalogCode())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store installations: list by catalog code: %v", err)
	}
	return installationListResponse(items), nil
}

func (s *InstallationsService) ListPendingByGateway(
	ctx context.Context,
	req *snapshotpb.ListByPrincipalRequest,
) (*snapshotpb.ListInstallationsResponse, error) {
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "list pending by gateway")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeGateway(ctx, "list pending by gateway", gatewayID); err != nil {
		return nil, err
	}
	items, err := s.repo.ListPendingByGateway(ctx, gatewayID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "store installations: list pending by gateway: %v", err)
	}
	return installationListResponse(items), nil
}

// Delete removes the installation for (gateway, principal, code), mapping a
// missing row to a NotFound status the client re-raises as ErrNotFound.
func (s *InstallationsService) Delete(
	ctx context.Context,
	req *snapshotpb.DeleteInstallationRequest,
) (*snapshotpb.DeleteInstallationResponse, error) {
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "delete")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeGateway(ctx, "delete", gatewayID); err != nil {
		return nil, err
	}
	if err := s.repo.Delete(ctx, gatewayID, req.GetPrincipalSub(), req.GetCatalogCode()); err != nil {
		if errors.Is(err, installationdomain.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "store installations: delete: not found")
		}
		return nil, status.Errorf(codes.Internal, "store installations: delete: %v", err)
	}
	return &snapshotpb.DeleteInstallationResponse{}, nil
}

func (s *InstallationsService) DeleteByID(
	ctx context.Context,
	req *snapshotpb.Installation,
) (*snapshotpb.DeleteInstallationResponse, error) {
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "delete by id")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeGateway(ctx, "delete by id", gatewayID); err != nil {
		return nil, err
	}
	id, err := parseInstallationID(req.GetId(), "delete by id")
	if err != nil {
		return nil, err
	}
	if err := s.repo.DeleteByID(ctx, gatewayID, req.GetPrincipalSub(), id); err != nil {
		if errors.Is(err, installationdomain.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "store installations: delete by id: not found")
		}
		return nil, status.Errorf(codes.Internal, "store installations: delete by id: %v", err)
	}
	return &snapshotpb.DeleteInstallationResponse{}, nil
}

// EnsureRegistry materialises the shared registry for a catalog code on the
// control plane's database, on behalf of a self-service install on the data
// plane. It is idempotent: the ensurer returns cleanly when the registry already
// exists. The new registry propagates back to the data plane through the normal
// ConfigSync snapshot.
func (s *InstallationsService) EnsureRegistry(
	ctx context.Context,
	req *snapshotpb.EnsureRegistryRequest,
) (*snapshotpb.EnsureRegistryResponse, error) {
	if s.ensurer == nil {
		return nil, status.Error(codes.Unimplemented, "store installations: registry materialisation is not available here")
	}
	gatewayID, err := parseGatewayID(req.GetGatewayId(), "ensure registry")
	if err != nil {
		return nil, err
	}
	if err := s.authorizeGateway(ctx, "ensure registry", gatewayID); err != nil {
		return nil, err
	}
	if err := s.ensurer.Ensure(ctx, gatewayID, req.GetCatalogCode()); err != nil {
		return nil, status.Errorf(codes.Internal, "store installations: ensure registry: %v", err)
	}
	return &snapshotpb.EnsureRegistryResponse{}, nil
}

// authorizeGateway enforces the caller's config-sync scope on the gateway a
// request names. The scope is what the auth interceptor derived from the
// caller's token — the gateway (instance) id for a per-instance JWT — and is
// empty for the unscoped shared-token deployment, which is allowed through like
// its snapshot is. A scoped caller passes when the gateway is the scoped one or,
// for a tenant-wide scope, when the gateway belongs to that tenant; an unknown
// gateway is NotFound and any other gateway PermissionDenied. Without a gateway
// resolver only the exact-gateway match can be honoured.
func (s *InstallationsService) authorizeGateway(ctx context.Context, op string, gatewayID ids.GatewayID) error {
	scope := ScopeFromContext(ctx)
	if scope == "" {
		return nil
	}
	if gatewayID.String() == scope {
		return nil
	}
	if s.gateways != nil {
		gw, err := s.gateways.FindByID(ctx, gatewayID)
		switch {
		case errors.Is(err, gatewaydomain.ErrNotFound), errors.Is(err, commonerrors.ErrNotFound):
			return status.Errorf(codes.NotFound, "store installations: %s: gateway not found", op)
		case err != nil:
			return status.Errorf(codes.Internal, "store installations: %s: resolve gateway: %v", op, err)
		}
		if tenant := gw.TenantID(); tenant != "" && tenant == scope {
			return nil
		}
	}
	s.logger.Warn("store installations: refusing request for a gateway outside the caller's scope",
		slog.String("component", component),
		slog.String("op", op),
		slog.String("scope", scope),
		slog.String("gateway_id", gatewayID.String()))
	return status.Errorf(codes.PermissionDenied, "store installations: %s: gateway is outside the caller's scope", op)
}

// validateDataPlaneInstallation applies the installation domain's invariants to
// a record that arrived over the wire (installationFromProto builds the struct
// directly, bypassing the constructor) plus the one rule specific to this
// channel: the data plane only ever records self-service installs, so the
// installer is the principal. An installed_by that names someone else would let
// a data plane forge a provisioned-by-admin row.
func validateDataPlaneInstallation(in *installationdomain.Installation) error {
	if err := in.Validate(); err != nil {
		return status.Errorf(codes.InvalidArgument, "store installations: upsert: %v", err)
	}
	if in.InstalledBy != "" && in.InstalledBy != in.PrincipalSub {
		return status.Error(codes.PermissionDenied, "store installations: upsert: installed_by must be the principal")
	}
	return nil
}

func parseGatewayID(raw, op string) (ids.GatewayID, error) {
	gatewayID, err := ids.Parse[ids.GatewayKind](raw)
	if err != nil {
		return ids.GatewayID{}, status.Errorf(codes.InvalidArgument, "store installations: %s: parse gateway id: %v", op, err)
	}
	if gatewayID.IsNil() {
		return ids.GatewayID{}, status.Errorf(codes.InvalidArgument, "store installations: %s: gateway id is required", op)
	}
	return gatewayID, nil
}

func parseInstallationID(raw, op string) (ids.InstallationID, error) {
	id, err := ids.Parse[ids.InstallationKind](raw)
	if err != nil {
		return ids.InstallationID{}, status.Errorf(codes.InvalidArgument, "store installations: %s: parse installation id: %v", op, err)
	}
	if id.IsNil() {
		return ids.InstallationID{}, status.Errorf(codes.InvalidArgument, "store installations: %s: installation id is required", op)
	}
	return id, nil
}

func installationListResponse(items []*installationdomain.Installation) *snapshotpb.ListInstallationsResponse {
	out := make([]*snapshotpb.Installation, 0, len(items))
	for _, in := range items {
		out = append(out, installationToProto(in))
	}
	return &snapshotpb.ListInstallationsResponse{Installations: out}
}
