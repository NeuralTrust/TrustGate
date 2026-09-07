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

	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	googlegrpc "google.golang.org/grpc"
)

const installationOperationsServiceName = "snapshotpb.InstallationOperations"

type installationOperationsClient struct {
	cc googlegrpc.ClientConnInterface
}

func (c installationOperationsClient) upsertCanonical(ctx context.Context, req *snapshotpb.UpsertInstallationRequest) (*snapshotpb.FindInstallationResponse, error) {
	out := new(snapshotpb.FindInstallationResponse)
	err := c.cc.Invoke(ctx, "/"+installationOperationsServiceName+"/UpsertCanonical", req, out)
	return out, err
}

func (c installationOperationsClient) findByID(ctx context.Context, req *snapshotpb.Installation) (*snapshotpb.FindInstallationResponse, error) {
	out := new(snapshotpb.FindInstallationResponse)
	err := c.cc.Invoke(ctx, "/"+installationOperationsServiceName+"/FindByID", req, out)
	return out, err
}

func (c installationOperationsClient) listByPrincipalAndCode(ctx context.Context, req *snapshotpb.FindInstallationRequest) (*snapshotpb.ListInstallationsResponse, error) {
	out := new(snapshotpb.ListInstallationsResponse)
	err := c.cc.Invoke(ctx, "/"+installationOperationsServiceName+"/ListByPrincipalAndCode", req, out)
	return out, err
}

func (c installationOperationsClient) listByCatalogCode(ctx context.Context, req *snapshotpb.FindInstallationRequest) (*snapshotpb.ListInstallationsResponse, error) {
	out := new(snapshotpb.ListInstallationsResponse)
	err := c.cc.Invoke(ctx, "/"+installationOperationsServiceName+"/ListByCatalogCode", req, out)
	return out, err
}

func (c installationOperationsClient) listPendingByGateway(ctx context.Context, req *snapshotpb.ListByPrincipalRequest) (*snapshotpb.ListInstallationsResponse, error) {
	out := new(snapshotpb.ListInstallationsResponse)
	err := c.cc.Invoke(ctx, "/"+installationOperationsServiceName+"/ListPendingByGateway", req, out)
	return out, err
}

func (c installationOperationsClient) deleteByID(ctx context.Context, req *snapshotpb.Installation) (*snapshotpb.DeleteInstallationResponse, error) {
	out := new(snapshotpb.DeleteInstallationResponse)
	err := c.cc.Invoke(ctx, "/"+installationOperationsServiceName+"/DeleteByID", req, out)
	return out, err
}

type installationOperationsServer interface {
	UpsertCanonical(context.Context, *snapshotpb.UpsertInstallationRequest) (*snapshotpb.FindInstallationResponse, error)
	FindByID(context.Context, *snapshotpb.Installation) (*snapshotpb.FindInstallationResponse, error)
	ListByPrincipalAndCode(context.Context, *snapshotpb.FindInstallationRequest) (*snapshotpb.ListInstallationsResponse, error)
	ListByCatalogCode(context.Context, *snapshotpb.FindInstallationRequest) (*snapshotpb.ListInstallationsResponse, error)
	ListPendingByGateway(context.Context, *snapshotpb.ListByPrincipalRequest) (*snapshotpb.ListInstallationsResponse, error)
	DeleteByID(context.Context, *snapshotpb.Installation) (*snapshotpb.DeleteInstallationResponse, error)
}

func registerInstallationOperationsServer(registrar googlegrpc.ServiceRegistrar, service installationOperationsServer) {
	registrar.RegisterService(&installationOperationsServiceDesc, service)
}

func unaryInstallationOperation[Req any, Resp any](
	method string,
	call func(installationOperationsServer, context.Context, *Req) (*Resp, error),
) googlegrpc.MethodDesc {
	return googlegrpc.MethodDesc{
		MethodName: method,
		Handler: func(srv any, ctx context.Context, decode func(any) error, interceptor googlegrpc.UnaryServerInterceptor) (any, error) {
			in := new(Req)
			if err := decode(in); err != nil {
				return nil, err
			}
			if interceptor == nil {
				return call(srv.(installationOperationsServer), ctx, in)
			}
			info := &googlegrpc.UnaryServerInfo{Server: srv, FullMethod: "/" + installationOperationsServiceName + "/" + method}
			handler := func(ctx context.Context, req any) (any, error) {
				return call(srv.(installationOperationsServer), ctx, req.(*Req))
			}
			return interceptor(ctx, in, info, handler)
		},
	}
}

var installationOperationsServiceDesc = googlegrpc.ServiceDesc{
	ServiceName: installationOperationsServiceName,
	HandlerType: (*installationOperationsServer)(nil),
	Methods: []googlegrpc.MethodDesc{
		unaryInstallationOperation("UpsertCanonical", func(s installationOperationsServer, ctx context.Context, req *snapshotpb.UpsertInstallationRequest) (*snapshotpb.FindInstallationResponse, error) {
			return s.UpsertCanonical(ctx, req)
		}),
		unaryInstallationOperation("FindByID", func(s installationOperationsServer, ctx context.Context, req *snapshotpb.Installation) (*snapshotpb.FindInstallationResponse, error) {
			return s.FindByID(ctx, req)
		}),
		unaryInstallationOperation("ListByPrincipalAndCode", func(s installationOperationsServer, ctx context.Context, req *snapshotpb.FindInstallationRequest) (*snapshotpb.ListInstallationsResponse, error) {
			return s.ListByPrincipalAndCode(ctx, req)
		}),
		unaryInstallationOperation("ListByCatalogCode", func(s installationOperationsServer, ctx context.Context, req *snapshotpb.FindInstallationRequest) (*snapshotpb.ListInstallationsResponse, error) {
			return s.ListByCatalogCode(ctx, req)
		}),
		unaryInstallationOperation("ListPendingByGateway", func(s installationOperationsServer, ctx context.Context, req *snapshotpb.ListByPrincipalRequest) (*snapshotpb.ListInstallationsResponse, error) {
			return s.ListPendingByGateway(ctx, req)
		}),
		unaryInstallationOperation("DeleteByID", func(s installationOperationsServer, ctx context.Context, req *snapshotpb.Installation) (*snapshotpb.DeleteInstallationResponse, error) {
			return s.DeleteByID(ctx, req)
		}),
	},
	Metadata: "installation_operations",
}
