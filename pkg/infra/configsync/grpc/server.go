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
	"errors"
	"fmt"
	"log/slog"
	"net"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/keepalive"
)

// Server wraps a *grpc.Server and its listener, implementing the shared
// server.Server Run/Shutdown lifecycle contract so the control-plane gRPC
// listener slots into the shared serve loop.
type Server struct {
	srv    *grpc.Server
	lis    net.Listener
	logger *slog.Logger
}

// NewServer builds the control-plane ConfigSync gRPC listener with TLS (when
// configured), the auth interceptors, and keepalive enforcement.
func NewServer(cfg config.ConfigSyncConfig, svc snapshotpb.ConfigSyncServer, auth *AuthInterceptor, logger *slog.Logger) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	creds, err := serverTransportCredentials(cfg)
	if err != nil {
		return nil, err
	}
	opts := []grpc.ServerOption{
		grpc.ChainUnaryInterceptor(auth.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(auth.StreamServerInterceptor()),
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:    cfg.GRPCKeepaliveTime,
			Timeout: cfg.GRPCKeepaliveTimeout,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             cfg.GRPCKeepaliveTime / 2,
			PermitWithoutStream: true,
		}),
	}
	if creds != nil {
		opts = append(opts, grpc.Creds(creds))
	}
	lis, err := net.Listen("tcp", cfg.GRPCListenAddr)
	if err != nil {
		return nil, fmt.Errorf("configsync: listen on %q: %w", cfg.GRPCListenAddr, err)
	}
	gsrv := grpc.NewServer(opts...)
	snapshotpb.RegisterConfigSyncServer(gsrv, svc)
	return &Server{srv: gsrv, lis: lis, logger: logger}, nil
}

// Run serves until Shutdown is called, mapping the graceful-stop signal to a
// clean nil return.
func (s *Server) Run() error {
	s.logger.Info("config-sync gRPC server listening",
		slog.String("component", component), slog.String("addr", s.lis.Addr().String()))
	if err := s.srv.Serve(s.lis); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return fmt.Errorf("configsync: serve: %w", err)
	}
	return nil
}

// Shutdown gracefully drains in-flight RPCs and stops the listener.
func (s *Server) Shutdown() error {
	s.srv.GracefulStop()
	return nil
}
