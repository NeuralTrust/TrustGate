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
	"fmt"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type InstallationsClient struct {
	cli snapshotpb.StoreInstallationsClient
	ops installationOperationsClient
}

func NewInstallationsClient(conn *grpc.ClientConn) *InstallationsClient {
	return &InstallationsClient{
		cli: snapshotpb.NewStoreInstallationsClient(conn),
		ops: installationOperationsClient{cc: conn},
	}
}

var _ installationdomain.Repository = (*InstallationsClient)(nil)

func (c *InstallationsClient) Upsert(ctx context.Context, in *installationdomain.Installation) error {
	resp, err := c.ops.upsertCanonical(ctx, &snapshotpb.UpsertInstallationRequest{
		Installation: installationToProto(in),
	})
	if err != nil {
		return fmt.Errorf("installations: upsert: %w", err)
	}
	canonical, err := installationFromProto(resp.GetInstallation())
	if err != nil {
		return fmt.Errorf("installations: upsert response: %w", err)
	}
	*in = *canonical
	return nil
}

func (c *InstallationsClient) Find(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, catalogCode string,
) (*installationdomain.Installation, error) {
	resp, err := c.cli.Find(ctx, &snapshotpb.FindInstallationRequest{
		GatewayId:    gatewayID.String(),
		PrincipalSub: principalSub,
		CatalogCode:  catalogCode,
	})
	if err != nil {
		return nil, fmt.Errorf("installations: find: %w", err)
	}
	if !resp.GetFound() {
		return nil, installationdomain.ErrNotFound
	}
	out, err := installationFromProto(resp.GetInstallation())
	if err != nil {
		return nil, fmt.Errorf("installations: find: %w", err)
	}
	return out, nil
}

func (c *InstallationsClient) ListByPrincipal(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
) ([]*installationdomain.Installation, error) {
	resp, err := c.cli.ListByPrincipal(ctx, &snapshotpb.ListByPrincipalRequest{
		GatewayId:    gatewayID.String(),
		PrincipalSub: principalSub,
	})
	if err != nil {
		return nil, fmt.Errorf("installations: list by principal: %w", err)
	}
	return installationsFromProto(resp.GetInstallations())
}

func (c *InstallationsClient) FindByID(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	id ids.InstallationID,
) (*installationdomain.Installation, error) {
	resp, err := c.ops.findByID(ctx, &snapshotpb.Installation{
		Id:           id.String(),
		GatewayId:    gatewayID.String(),
		PrincipalSub: principalSub,
	})
	if err != nil {
		return nil, fmt.Errorf("installations: find by id: %w", err)
	}
	if !resp.GetFound() {
		return nil, installationdomain.ErrNotFound
	}
	out, err := installationFromProto(resp.GetInstallation())
	if err != nil {
		return nil, fmt.Errorf("installations: find by id: %w", err)
	}
	return out, nil
}

func (c *InstallationsClient) ListByPrincipalAndCode(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, catalogCode string,
) ([]*installationdomain.Installation, error) {
	resp, err := c.ops.listByPrincipalAndCode(ctx, &snapshotpb.FindInstallationRequest{
		GatewayId:    gatewayID.String(),
		PrincipalSub: principalSub,
		CatalogCode:  catalogCode,
	})
	if err != nil {
		return nil, fmt.Errorf("installations: list by principal and code: %w", err)
	}
	return installationsFromProto(resp.GetInstallations())
}

func (c *InstallationsClient) Delete(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub, catalogCode string,
) error {
	_, err := c.cli.Delete(ctx, &snapshotpb.DeleteInstallationRequest{
		GatewayId:    gatewayID.String(),
		PrincipalSub: principalSub,
		CatalogCode:  catalogCode,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return installationdomain.ErrNotFound
		}
		return fmt.Errorf("installations: delete: %w", err)
	}
	return nil
}

func (c *InstallationsClient) DeleteByID(
	ctx context.Context,
	gatewayID ids.GatewayID,
	principalSub string,
	id ids.InstallationID,
) error {
	_, err := c.ops.deleteByID(ctx, &snapshotpb.Installation{
		Id:           id.String(),
		GatewayId:    gatewayID.String(),
		PrincipalSub: principalSub,
	})
	if err != nil {
		if status.Code(err) == codes.NotFound {
			return installationdomain.ErrNotFound
		}
		return fmt.Errorf("installations: delete by id: %w", err)
	}
	return nil
}

// Ensure asks the control plane to materialise the shared registry for a catalog
// code (the self-service "created on first install" path). It forwards over the
// same egress-only connection; the new registry syncs back through the normal
// ConfigSync snapshot. This makes the client an appstore.RegistryEnsurer.
func (c *InstallationsClient) Ensure(
	ctx context.Context,
	gatewayID ids.GatewayID,
	code string,
) error {
	if _, err := c.cli.EnsureRegistry(ctx, &snapshotpb.EnsureRegistryRequest{
		GatewayId:   gatewayID.String(),
		CatalogCode: code,
	}); err != nil {
		return fmt.Errorf("installations: ensure registry: %w", err)
	}
	return nil
}

func (c *InstallationsClient) ListByCatalogCode(
	ctx context.Context, gatewayID ids.GatewayID, catalogCode string,
) ([]*installationdomain.Installation, error) {
	resp, err := c.ops.listByCatalogCode(ctx, &snapshotpb.FindInstallationRequest{
		GatewayId:   gatewayID.String(),
		CatalogCode: catalogCode,
	})
	if err != nil {
		return nil, fmt.Errorf("installations: list by catalog code: %w", err)
	}
	return installationsFromProto(resp.GetInstallations())
}

func (c *InstallationsClient) ListPendingByGateway(
	ctx context.Context, gatewayID ids.GatewayID,
) ([]*installationdomain.Installation, error) {
	resp, err := c.ops.listPendingByGateway(ctx, &snapshotpb.ListByPrincipalRequest{
		GatewayId: gatewayID.String(),
	})
	if err != nil {
		return nil, fmt.Errorf("installations: list pending by gateway: %w", err)
	}
	return installationsFromProto(resp.GetInstallations())
}

func installationsFromProto(
	msgs []*snapshotpb.Installation,
) ([]*installationdomain.Installation, error) {
	out := make([]*installationdomain.Installation, 0, len(msgs))
	for _, msg := range msgs {
		in, err := installationFromProto(msg)
		if err != nil {
			return nil, fmt.Errorf("installations: decode: %w", err)
		}
		out = append(out, in)
	}
	return out, nil
}
