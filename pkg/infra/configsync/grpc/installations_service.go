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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// InstallationsService is the control-plane end of the StoreInstallations
// channel: it persists the per-principal Store install state on behalf of the
// DB-less data plane, delegating to the same installation repository the admin
// plane writes through. The data plane computes the install decision (catalog +
// registry governance) locally; only the durable write/read crosses to here.
type InstallationsService struct {
	snapshotpb.UnimplementedStoreInstallationsServer
	repo   installationdomain.Repository
	logger *slog.Logger
}

// NewInstallationsService builds the StoreInstallations server over the live
// installation repository.
func NewInstallationsService(repo installationdomain.Repository, logger *slog.Logger) *InstallationsService {
	if logger == nil {
		logger = slog.Default()
	}
	return &InstallationsService{repo: repo, logger: logger}
}

// Upsert persists one installation record minted by the data plane.
func (s *InstallationsService) Upsert(
	ctx context.Context,
	req *snapshotpb.UpsertInstallationRequest,
) (*snapshotpb.UpsertInstallationResponse, error) {
	in, err := installationFromProto(req.GetInstallation())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "store installations: upsert: %v", err)
	}
	if err := s.repo.Upsert(ctx, in); err != nil {
		return nil, status.Errorf(codes.Internal, "store installations: upsert: %v", err)
	}
	return &snapshotpb.UpsertInstallationResponse{}, nil
}

// Find returns the installation for (gateway, principal, code), reporting a
// missing row as found=false rather than an error.
func (s *InstallationsService) Find(
	ctx context.Context,
	req *snapshotpb.FindInstallationRequest,
) (*snapshotpb.FindInstallationResponse, error) {
	gatewayID, err := ids.Parse[ids.GatewayKind](req.GetGatewayId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "store installations: find: parse gateway id: %v", err)
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
	gatewayID, err := ids.Parse[ids.GatewayKind](req.GetGatewayId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "store installations: list: parse gateway id: %v", err)
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

// Delete removes the installation for (gateway, principal, code), mapping a
// missing row to a NotFound status the client re-raises as ErrNotFound.
func (s *InstallationsService) Delete(
	ctx context.Context,
	req *snapshotpb.DeleteInstallationRequest,
) (*snapshotpb.DeleteInstallationResponse, error) {
	gatewayID, err := ids.Parse[ids.GatewayKind](req.GetGatewayId())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "store installations: delete: parse gateway id: %v", err)
	}
	if err := s.repo.Delete(ctx, gatewayID, req.GetPrincipalSub(), req.GetCatalogCode()); err != nil {
		if errors.Is(err, installationdomain.ErrNotFound) {
			return nil, status.Error(codes.NotFound, "store installations: delete: not found")
		}
		return nil, status.Errorf(codes.Internal, "store installations: delete: %v", err)
	}
	return &snapshotpb.DeleteInstallationResponse{}, nil
}
