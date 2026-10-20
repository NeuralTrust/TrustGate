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
	"net"
	"sync"
	"testing"
	"time"

	appcsr "github.com/NeuralTrust/TrustGate/pkg/app/configsyncrevocation"
	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/golang-jwt/jwt/v5"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func revokingGate(mode appcsr.Mode, r configsyncrevocation.Revocations) appcsr.Gate {
	gate := appcsr.NewGate(mode, discardLogger())
	gate.Replace(configsyncrevocation.NewSnapshot(r))
	return gate
}

func revokedJTI(scope, jti string) configsyncrevocation.Revocations {
	return configsyncrevocation.Revocations{JTIs: []configsyncrevocation.JTIRevocation{{Scope: scope, JTI: jti}}}
}

func callUnary(t *testing.T, interceptor *AuthInterceptor, bearer string) (codes.Code, string, bool) {
	t.Helper()
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authMetadataKey, bearerPrefix+bearer))
	var (
		scope  string
		called bool
	)
	handler := func(ctx context.Context, _ any) (any, error) {
		scope, called = ScopeFromContext(ctx), true
		return nil, nil
	}
	_, err := interceptor.UnaryServerInterceptor()(ctx, nil, &grpc.UnaryServerInfo{}, handler)
	return status.Code(err), scope, called
}

func TestAuthInterceptor_RevocationModes(t *testing.T) {
	token := mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "jti-1", 100))
	cases := []struct {
		name string
		mode appcsr.Mode
		want codes.Code
	}{
		{"off ignores the revocation", appcsr.ModeOff, codes.OK},
		{"shadow admits the revoked token", appcsr.ModeShadow, codes.OK},
		{"enforce rejects the revoked token", appcsr.ModeEnforce, codes.Unauthenticated},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gate := revokingGate(tc.mode, revokedJTI("gw-1", "jti-1"))
			interceptor, err := NewAuthInterceptor(&config.Config{ConfigSync: newSignedTestConfig(t)}, discardLogger(), gate)
			if err != nil {
				t.Fatalf("NewAuthInterceptor: %v", err)
			}
			code, _, called := callUnary(t, interceptor, token)
			if code != tc.want || called != (tc.want == codes.OK) {
				t.Fatalf("code = %s, handler called = %v; want %s", code, called, tc.want)
			}
		})
	}
}

func TestAuthInterceptor_EnforceAnswersLikeAnInvalidToken(t *testing.T) {
	gate := revokingGate(appcsr.ModeEnforce, revokedJTI("gw-1", "jti-1"))
	interceptor, err := NewAuthInterceptor(&config.Config{ConfigSync: newSignedTestConfig(t)}, discardLogger(), gate)
	if err != nil {
		t.Fatalf("NewAuthInterceptor: %v", err)
	}
	revoked := mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "jti-1", 100))
	authorize := func(bearer string) error {
		ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs(authMetadataKey, bearerPrefix+bearer))
		_, err := interceptor.authorize(ctx)
		return err
	}
	revokedErr, garbageErr := authorize(revoked), authorize("not-a-token")
	if revokedErr == nil || revokedErr.Error() != garbageErr.Error() {
		t.Fatalf("revoked error %v, want the same error as a garbage token (%v)", revokedErr, garbageErr)
	}
}

func TestAuthInterceptor_EnforceKeepsOtherTokens(t *testing.T) {
	gate := revokingGate(appcsr.ModeEnforce, configsyncrevocation.Revocations{
		JTIs:  []configsyncrevocation.JTIRevocation{{Scope: "gw-1", JTI: "jti-1"}},
		Marks: []configsyncrevocation.IssuedBeforeMark{{Scope: "gw-1", IssuedBefore: 1000}},
	})
	interceptor, err := NewAuthInterceptor(&config.Config{ConfigSync: newSignedTestConfig(t)}, discardLogger(), gate)
	if err != nil {
		t.Fatalf("NewAuthInterceptor: %v", err)
	}
	cases := []struct {
		name   string
		claims jwt.MapClaims
		want   codes.Code
	}{
		{"replacement token issued at the mark", instanceClaims("gw-1", "jti-new", 1000), codes.OK},
		{"token issued before the mark", instanceClaims("gw-1", "jti-old", 999), codes.Unauthenticated},
		{"same jti under another instance", instanceClaims("gw-2", "jti-1", 10), codes.OK},
		{"token without jti or iat", instanceClaims("gw-1", "", 0), codes.OK},
		{"legacy scope-only token", validClaims(), codes.OK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := callUnary(t, interceptor, mint(t, testSecret, jwt.SigningMethodHS256, tc.claims))
			if code != tc.want {
				t.Fatalf("code = %s, want %s", code, tc.want)
			}
		})
	}
}

func TestAuthInterceptor_CompositeRevocationNeverFallsBackToShared(t *testing.T) {
	cfg := newSignedTestConfig(t)
	cfg.AuthMode = config.ConfigSyncAuthModeComposite
	cfg.Token = "shared-tok"
	gate := revokingGate(appcsr.ModeEnforce, configsyncrevocation.Revocations{
		JTIs:  []configsyncrevocation.JTIRevocation{{Scope: "gw-1", JTI: "jti-1"}},
		Marks: []configsyncrevocation.IssuedBeforeMark{{Scope: "", IssuedBefore: time.Now().Unix()}},
	})
	interceptor, err := NewAuthInterceptor(&config.Config{ConfigSync: cfg}, discardLogger(), gate)
	if err != nil {
		t.Fatalf("NewAuthInterceptor: %v", err)
	}
	revoked := mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "jti-1", 100))
	if code, scope, called := callUnary(t, interceptor, revoked); code != codes.Unauthenticated || called {
		t.Fatalf("revoked JWT: code = %s, scope = %q, called = %v; want Unauthenticated", code, scope, called)
	}
	if code, scope, called := callUnary(t, interceptor, "shared-tok"); code != codes.OK || !called || scope != "" {
		t.Fatalf("shared token: code = %s, scope = %q, called = %v; want OK with the global scope", code, scope, called)
	}
}

func TestHub_CloseRevoked(t *testing.T) {
	h := NewHub(discardLogger(), nil)
	revoked := h.register(configsyncrevocation.Identity{Scope: "gw-1", JTI: "old", Signed: true, InstanceScoped: true}, "dp-1")
	sibling := h.register(configsyncrevocation.Identity{Scope: "gw-1", JTI: "new", Signed: true, InstanceScoped: true}, "dp-2")
	gone := h.register(configsyncrevocation.Identity{Scope: "gw-1", JTI: "old", Signed: true, InstanceScoped: true}, "dp-3")
	h.unregister(gone)
	isRevoked := func(id configsyncrevocation.Identity) bool { return id.JTI == "old" }

	if closed := h.CloseRevoked(isRevoked); closed != 1 {
		t.Fatalf("first pass closed %d streams, want 1", closed)
	}
	select {
	case <-revoked.revoked:
	default:
		t.Fatal("revoked stream was not closed")
	}
	select {
	case <-sibling.revoked:
		t.Fatal("stream with a valid token was closed")
	default:
	}
	select {
	case <-gone.revoked:
		t.Fatal("unregistered stream was touched")
	default:
	}
	if closed := h.CloseRevoked(isRevoked); closed != 0 {
		t.Fatalf("second pass closed %d streams, want 0", closed)
	}
}

func TestHub_CloseRevokedConcurrentWithRegister(t *testing.T) {
	h := NewHub(discardLogger(), nil)
	isRevoked := func(id configsyncrevocation.Identity) bool { return id.JTI == "old" }
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			jti := "old"
			if i%2 == 0 {
				jti = "new"
			}
			conn := h.register(configsyncrevocation.Identity{Scope: "gw-1", JTI: jti}, "dp")
			h.unregister(conn)
		}()
		go func() {
			defer wg.Done()
			h.CloseRevoked(isRevoked)
		}()
	}
	wg.Wait()
	if n := h.ConnectionCount(); n != 0 {
		t.Fatalf("ConnectionCount = %d, want 0", n)
	}
}

func newAuthedBufServer(t *testing.T, cfg config.ConfigSyncConfig, svc *Service, gate TokenGate) *bufconn.Listener {
	t.Helper()
	auth, err := NewAuthInterceptor(&config.Config{ConfigSync: cfg}, discardLogger(), gate)
	if err != nil {
		t.Fatalf("NewAuthInterceptor: %v", err)
	}
	lis := bufconn.Listen(1 << 20)
	gsrv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(auth.UnaryServerInterceptor()),
		grpc.ChainStreamInterceptor(auth.StreamServerInterceptor()),
	)
	snapshotpb.RegisterConfigSyncServer(gsrv, svc)
	go func() { _ = gsrv.Serve(lis) }()
	t.Cleanup(gsrv.Stop)
	return lis
}

func dialAuthed(t *testing.T, lis *bufconn.Listener, token string) (snapshotpb.ConfigSyncClient, context.Context) {
	t.Helper()
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	ctx, cancel := context.WithCancel(metadata.AppendToOutgoingContext(context.Background(), authMetadataKey, bearerPrefix+token))
	t.Cleanup(cancel)
	return snapshotpb.NewConfigSyncClient(conn), ctx
}

func openSync(t *testing.T, lis *bufconn.Listener, token string) snapshotpb.ConfigSync_SyncClient {
	t.Helper()
	client, ctx := dialAuthed(t, lis, token)
	stream, err := client.Sync(ctx)
	if err != nil {
		t.Fatalf("open sync: %v", err)
	}
	hello := &snapshotpb.ClientMessage{Msg: &snapshotpb.ClientMessage_Hello{Hello: &snapshotpb.Hello{InstanceId: "dp"}}}
	if err := stream.Send(hello); err != nil {
		t.Fatalf("send hello: %v", err)
	}
	return stream
}

func recvCodeAsync(stream snapshotpb.ConfigSync_SyncClient) <-chan codes.Code {
	result := make(chan codes.Code, 1)
	go func() {
		for {
			if _, err := stream.Recv(); err != nil {
				result <- status.Code(err)
				return
			}
		}
	}()
	return result
}

func recvCode(t *testing.T, stream snapshotpb.ConfigSync_SyncClient) codes.Code {
	t.Helper()
	select {
	case code := <-recvCodeAsync(stream):
		return code
	case <-time.After(5 * time.Second):
		t.Fatal("stream did not end")
		return codes.OK
	}
}

func TestService_SyncEndsWhenTokenIsRevokedWhileOpen(t *testing.T) {
	gate := appcsr.NewGate(appcsr.ModeEnforce, discardLogger())
	hub := NewHub(discardLogger(), nil)
	lis := newAuthedBufServer(t, newSignedTestConfig(t), NewService(hub, &fakeSource{}, discardLogger(), gate), gate)

	old := openSync(t, lis, mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "old", 100)))
	fresh := openSync(t, lis, mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "new", 200)))
	eventually(t, func() bool { return hub.ConnectionCount() == 2 }, "streams never registered")

	gate.Replace(configsyncrevocation.NewSnapshot(revokedJTI("gw-1", "old")))
	if closed := hub.CloseRevoked(gate.Revoked); closed != 1 {
		t.Fatalf("CloseRevoked closed %d streams, want 1", closed)
	}
	if code := recvCode(t, old); code != codes.Unauthenticated {
		t.Fatalf("revoked stream ended with %s, want Unauthenticated", code)
	}
	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "revoked stream still registered")
	select {
	case <-time.After(100 * time.Millisecond):
	case code := <-recvCodeAsync(fresh):
		t.Fatalf("stream with a valid token ended with %s", code)
	}
}

func TestService_SyncRechecksAfterRegister(t *testing.T) {
	gate := revokingGate(appcsr.ModeEnforce, revokedJTI("gw-1", "old"))
	hub := NewHub(discardLogger(), nil)
	// The interceptor runs without a gate here, standing in for a stream that
	// was admitted just before the revocation was loaded.
	lis := newAuthedBufServer(t, newSignedTestConfig(t), NewService(hub, &fakeSource{}, discardLogger(), gate), nil)

	stream := openSync(t, lis, mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "old", 100)))
	if code := recvCode(t, stream); code != codes.Unauthenticated {
		t.Fatalf("stream ended with %s, want Unauthenticated", code)
	}
	eventually(t, func() bool { return hub.ConnectionCount() == 0 }, "revoked stream still registered")
}

func TestService_ShadowNeverClosesStreams(t *testing.T) {
	gate := revokingGate(appcsr.ModeShadow, revokedJTI("gw-1", "old"))
	hub := NewHub(discardLogger(), nil)
	lis := newAuthedBufServer(t, newSignedTestConfig(t), NewService(hub, &fakeSource{}, discardLogger(), gate), gate)

	_ = openSync(t, lis, mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "old", 100)))
	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "stream never registered")
	if closed := hub.CloseRevoked(gate.Revoked); closed != 0 {
		t.Fatalf("shadow closed %d streams, want 0", closed)
	}
	if n := hub.ConnectionCount(); n != 1 {
		t.Fatalf("ConnectionCount = %d, want the shadow stream still open", n)
	}
}

func TestService_EnforceRejectsRevokedGetSnapshot(t *testing.T) {
	gate := revokingGate(appcsr.ModeEnforce, revokedJTI("gw-1", "old"))
	src := &fakeSource{}
	src.set([]byte("payload"), "v1")
	lis := newAuthedBufServer(t, newSignedTestConfig(t), NewService(NewHub(discardLogger(), nil), src, discardLogger(), gate), gate)

	client, ctx := dialAuthed(t, lis, mint(t, testSecret, jwt.SigningMethodHS256, instanceClaims("gw-1", "old", 100)))
	stream, err := client.GetSnapshot(ctx, &snapshotpb.GetSnapshotRequest{})
	if err == nil {
		_, err = stream.Recv()
	}
	if code := status.Code(err); code != codes.Unauthenticated {
		t.Fatalf("GetSnapshot with a revoked token = %s, want Unauthenticated before any chunk", code)
	}
}

func TestService_EnforceNeverClosesSharedTokenStreams(t *testing.T) {
	cfg := newSignedTestConfig(t)
	cfg.AuthMode = config.ConfigSyncAuthModeComposite
	cfg.Token = "shared-tok"
	gate := revokingGate(appcsr.ModeEnforce, configsyncrevocation.Revocations{
		Marks: []configsyncrevocation.IssuedBeforeMark{{Scope: "", IssuedBefore: time.Now().Add(time.Minute).Unix()}},
	})
	hub := NewHub(discardLogger(), nil)
	lis := newAuthedBufServer(t, cfg, NewService(hub, &fakeSource{}, discardLogger(), gate), gate)

	stream := openSync(t, lis, "shared-tok")
	eventually(t, func() bool { return hub.ConnectionCount() == 1 }, "shared-token stream never registered")
	if closed := hub.CloseRevoked(gate.Revoked); closed != 0 {
		t.Fatalf("CloseRevoked closed %d shared-token streams, want 0", closed)
	}
	select {
	case code := <-recvCodeAsync(stream):
		t.Fatalf("shared-token stream ended with %s", code)
	case <-time.After(100 * time.Millisecond):
	}
}
