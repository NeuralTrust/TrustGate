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
	"io"
	"log/slog"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

func testInterceptor(token, previous string) *AuthInterceptor {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := &config.Config{ConfigSync: config.ConfigSyncConfig{Token: token, TokenPrevious: previous}}
	return NewAuthInterceptor(cfg, logger)
}

func contextWithAuth(header string, set bool) context.Context {
	ctx := context.Background()
	if !set {
		return ctx
	}
	return metadata.NewIncomingContext(ctx, metadata.Pairs(authMetadataKey, header))
}

type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f fakeServerStream) Context() context.Context { return f.ctx }

func codeOf(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	return status.Code(err)
}

type authCase struct {
	name     string
	token    string
	previous string
	header   string
	setMeta  bool
	want     codes.Code
}

func authCases() []authCase {
	const token = "a-strong-config-sync-token"
	return []authCase{
		{"valid token passes", token, "", bearerPrefix + token, true, codes.OK},
		{"previous token passes during rotation", "new-token", "old-token", bearerPrefix + "old-token", true, codes.OK},
		{"current token passes during rotation", "new-token", "old-token", bearerPrefix + "new-token", true, codes.OK},
		{"wrong token rejected", token, "", bearerPrefix + "wrong-token", true, codes.Unauthenticated},
		{"unknown token rejected during rotation", "new-token", "old-token", bearerPrefix + "other", true, codes.Unauthenticated},
		{"missing metadata rejected", token, "", "", false, codes.Unauthenticated},
		{"non-bearer header rejected", token, "", token, true, codes.Unauthenticated},
		{"unconfigured token fails closed", "", "", bearerPrefix + token, true, codes.Unauthenticated},
		{"previous alone without current fails closed", "", "old-token", bearerPrefix + "old-token", true, codes.Unauthenticated},
	}
}

func TestAuthInterceptor_Unary(t *testing.T) {
	for _, tc := range authCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			interceptor := testInterceptor(tc.token, tc.previous)
			ctx := contextWithAuth(tc.header, tc.setMeta)
			called := false
			handler := func(context.Context, any) (any, error) {
				called = true
				return "ok", nil
			}
			_, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{}, handler)
			if got := codeOf(err); got != tc.want {
				t.Fatalf("code = %s, want %s", got, tc.want)
			}
			if wantCalled := tc.want == codes.OK; called != wantCalled {
				t.Fatalf("handler called = %v, want %v", called, wantCalled)
			}
		})
	}
}

func TestAuthInterceptor_Stream(t *testing.T) {
	for _, tc := range authCases() {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			interceptor := testInterceptor(tc.token, tc.previous)
			ctx := contextWithAuth(tc.header, tc.setMeta)
			called := false
			handler := func(any, grpc.ServerStream) error {
				called = true
				return nil
			}
			err := interceptor.StreamServerInterceptor()(nil, fakeServerStream{ctx: ctx}, &grpc.StreamServerInfo{}, handler)
			if got := codeOf(err); got != tc.want {
				t.Fatalf("code = %s, want %s", got, tc.want)
			}
			if wantCalled := tc.want == codes.OK; called != wantCalled {
				t.Fatalf("handler called = %v, want %v", called, wantCalled)
			}
		})
	}
}
