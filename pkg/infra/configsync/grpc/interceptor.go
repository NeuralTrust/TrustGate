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

// Package grpc implements the config-sync gRPC transport: the control-plane
// server, the data-plane client, the connection hub, and the auth interceptors
// and credentials that secure the channel.
package grpc

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	authMetadataKey = "authorization"
	bearerPrefix    = "Bearer "
	component       = "configsync-grpc"
)

// AuthInterceptor authenticates config-sync RPCs by comparing the presented
// bearer token digest against the configured current and previous token digests
// with a constant-time compare. It fails closed when no token is configured.
type AuthInterceptor struct {
	tokenDigests [][32]byte
	logger       *slog.Logger
}

// NewAuthInterceptor builds an AuthInterceptor from the config-sync tokens,
// warning once when no token is configured so the operator learns the transport
// will reject every RPC.
func NewAuthInterceptor(cfg *config.Config, logger *slog.Logger) *AuthInterceptor {
	if logger == nil {
		logger = slog.Default()
	}
	interceptor := &AuthInterceptor{logger: logger}
	if cfg.ConfigSync.Token != "" {
		interceptor.tokenDigests = append(interceptor.tokenDigests, sha256.Sum256([]byte(cfg.ConfigSync.Token)))
		if cfg.ConfigSync.TokenPrevious != "" {
			interceptor.tokenDigests = append(interceptor.tokenDigests, sha256.Sum256([]byte(cfg.ConfigSync.TokenPrevious)))
		}
	} else {
		logger.Warn("config-sync token is not configured; the gRPC transport will reject every RPC and no data plane can converge",
			slog.String("component", component))
	}
	return interceptor
}

// UnaryServerInterceptor authenticates unary RPCs before the handler runs.
func (a *AuthInterceptor) UnaryServerInterceptor() grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		if err := a.authorize(ctx); err != nil {
			return nil, err
		}
		return handler(ctx, req)
	}
}

// StreamServerInterceptor authenticates streaming RPCs before the handler runs.
func (a *AuthInterceptor) StreamServerInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		if err := a.authorize(ss.Context()); err != nil {
			return err
		}
		return handler(srv, ss)
	}
}

func (a *AuthInterceptor) authorize(ctx context.Context) error {
	if len(a.tokenDigests) == 0 {
		a.logger.Debug("config-sync token is not configured; rejecting RPC",
			slog.String("component", component))
		return status.Error(codes.Unauthenticated, "config-sync token is not configured")
	}
	provided := bearerFromContext(ctx)
	if provided == "" {
		return status.Error(codes.Unauthenticated, "missing or invalid config-sync token")
	}
	providedDigest := sha256.Sum256([]byte(provided))
	matched := 0
	for _, digest := range a.tokenDigests {
		matched |= subtle.ConstantTimeCompare(providedDigest[:], digest[:])
	}
	if matched != 1 {
		return status.Error(codes.Unauthenticated, "missing or invalid config-sync token")
	}
	return nil
}

func bearerFromContext(ctx context.Context) string {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return ""
	}
	values := md.Get(authMetadataKey)
	if len(values) == 0 {
		return ""
	}
	header := values[0]
	if !strings.HasPrefix(header, bearerPrefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, bearerPrefix))
}
