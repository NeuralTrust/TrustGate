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
	auth := NewAuthInterceptor(&config.Config{ConfigSync: config.ConfigSyncConfig{Token: "tok"}}, discardLogger())
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
