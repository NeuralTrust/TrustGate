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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// errDataPlaneAdminUnsupported guards the admin-only read methods of the
// installation repository. The data plane's Store surface only ever installs,
// uninstalls, finds and lists-by-principal; the admin queues (list-by-code,
// list-pending) run on the control plane against the DB directly and are never
// invoked here. Failing loudly beats a silent empty result if that ever changes.
var errDataPlaneAdminUnsupported = errors.New(
	"installations: admin queries are not served over the data-plane channel")

// InstallationsClient is the data-plane end of the StoreInstallations channel. It
// implements installationdomain.Repository by delegating the durable read/write
// to the control plane over the same egress-only gRPC connection the config-sync
// client already holds, so the DB-less data plane can persist Store installs.
type InstallationsClient struct {
	cli snapshotpb.StoreInstallationsClient
}

// NewInstallationsClient builds the repository over an existing gRPC connection
// (the config-sync dial), so no second connection or dial is opened.
func NewInstallationsClient(conn *grpc.ClientConn) *InstallationsClient {
	return &InstallationsClient{cli: snapshotpb.NewStoreInstallationsClient(conn)}
}

var _ installationdomain.Repository = (*InstallationsClient)(nil)

func (c *InstallationsClient) Upsert(ctx context.Context, in *installationdomain.Installation) error {
	if _, err := c.cli.Upsert(ctx, &snapshotpb.UpsertInstallationRequest{
		Installation: installationToProto(in),
	}); err != nil {
		return fmt.Errorf("installations: upsert: %w", err)
	}
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

// ListByCatalogCode is an admin read served only on the control plane.
func (c *InstallationsClient) ListByCatalogCode(
	context.Context, ids.GatewayID, string,
) ([]*installationdomain.Installation, error) {
	return nil, errDataPlaneAdminUnsupported
}

// ListPendingByGateway is an admin read served only on the control plane.
func (c *InstallationsClient) ListPendingByGateway(
	context.Context, ids.GatewayID,
) ([]*installationdomain.Installation, error) {
	return nil, errDataPlaneAdminUnsupported
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
