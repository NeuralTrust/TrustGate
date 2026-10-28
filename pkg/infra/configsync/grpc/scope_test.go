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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestScopeContextRoundTrip(t *testing.T) {
	ctx := WithScope(context.Background(), "org_42")
	if got := ScopeFromContext(ctx); got != "org_42" {
		t.Fatalf("scope = %q, want org_42", got)
	}
	if got := ScopeFromContext(context.Background()); got != "" {
		t.Fatalf("missing scope = %q, want empty", got)
	}
}

type recordingStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *recordingStream) Context() context.Context { return s.ctx }

func TestStreamInterceptorInjectsScope(t *testing.T) {
	auth, err := NewAuthInterceptor(&config.Config{ConfigSync: config.ConfigSyncConfig{Token: "tok"}}, discardLogger(), nil)
	if err != nil {
		t.Fatalf("NewAuthInterceptor: %v", err)
	}
	md := metadata.New(map[string]string{authMetadataKey: bearerPrefix + "tok"})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	var seen string
	invoked := false
	handler := func(_ any, ss grpc.ServerStream) error {
		seen = ScopeFromContext(ss.Context())
		invoked = true
		return nil
	}
	if err := auth.StreamServerInterceptor()(nil, &recordingStream{ctx: ctx}, &grpc.StreamServerInfo{}, handler); err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	if !invoked {
		t.Fatal("handler was not invoked")
	}
	if seen != "" {
		t.Fatalf("shared-mode scope = %q, want empty", seen)
	}
}

func TestIdentityContextRoundTrip(t *testing.T) {
	want := configsyncrevocation.Identity{Scope: "gw-1", JTI: "j", IssuedAt: 7, Signed: true, InstanceScoped: true}
	got, ok := IdentityFromContext(WithIdentity(context.Background(), want))
	if !ok || got != want {
		t.Fatalf("IdentityFromContext = (%+v, %v), want (%+v, true)", got, ok, want)
	}
	if _, ok := IdentityFromContext(context.Background()); ok {
		t.Fatal("IdentityFromContext on a bare context reported an identity")
	}
}

func TestStreamInterceptorInjectsSignedIdentity(t *testing.T) {
	cfg := newSignedTestConfig(t)
	auth, err := NewAuthInterceptor(&config.Config{ConfigSync: cfg}, discardLogger(), nil)
	if err != nil {
		t.Fatalf("NewAuthInterceptor: %v", err)
	}
	token := mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "jti-1", 100))
	md := metadata.New(map[string]string{authMetadataKey: bearerPrefix + token})
	ctx := metadata.NewIncomingContext(context.Background(), md)

	var (
		seenScope string
		seenID    configsyncrevocation.Identity
		hasID     bool
	)
	handler := func(_ any, ss grpc.ServerStream) error {
		seenScope = ScopeFromContext(ss.Context())
		seenID, hasID = IdentityFromContext(ss.Context())
		return nil
	}
	if err := auth.StreamServerInterceptor()(nil, &recordingStream{ctx: ctx}, &grpc.StreamServerInfo{}, handler); err != nil {
		t.Fatalf("interceptor: %v", err)
	}
	want := configsyncrevocation.Identity{Scope: "gw-1", JTI: "jti-1", IssuedAt: 100, Signed: true, InstanceScoped: true}
	if seenScope != "gw-1" || !hasID || seenID != want {
		t.Fatalf("scope = %q, identity = (%+v, %v); want gw-1 and %+v", seenScope, seenID, hasID, want)
	}
}
