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

package oauth

import (
	"context"
	"testing"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

// The MCP plane keeps serving a client the tool list it fetched when it
// connected. It knows when that was from the session token: the login that
// opened the session, stamped at the exchange.
func TestExchangeCodeStampsWhenTheClientConnected(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	issued := time.Date(2026, 11, 2, 9, 30, 0, 0, time.UTC)
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, signer, nil).(*authProxy)
	// The exchange runs minutes after the login; the login is the connection.
	proxy.now = fixedClock(issued.Add(3 * time.Minute))
	if err := store.SaveCode(context.Background(), "gw-code", CodeGrant{
		RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge: s256("client-verifier"),
		Subject:       "user-42",
		AuthID:        appauth.DefaultIdPAuthID().String(),
		GatewayID:     "11111111-1111-1111-1111-111111111111",
		SessionMode:   true,
		IssuedAt:      issued,
	}); err != nil {
		t.Fatalf("save code: %v", err)
	}
	resp, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         "gw-code",
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	got, ok := mintedSessionClaims(t, signer, resp)[identity.ClaimMCPSessionStart].(float64)
	if !ok || int64(got) != issued.Unix() {
		t.Fatalf("mcp_session_start = %v, want %d", got, issued.Unix())
	}
}

// A code stored before codes carried their issue time still opens a session
// with a connection time: the exchange's own clock.
func TestExchangeCodeWithoutIssueTimeStampsTheExchange(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	now := time.Date(2026, 11, 2, 9, 30, 0, 0, time.UTC)
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, signer, nil).(*authProxy)
	proxy.now = fixedClock(now)
	if err := store.SaveCode(context.Background(), "gw-code", CodeGrant{
		RedirectURI:   "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeChallenge: s256("client-verifier"),
		Subject:       "user-42",
		AuthID:        "auth-1",
		SessionMode:   true,
	}); err != nil {
		t.Fatalf("save code: %v", err)
	}
	resp, err := proxy.Exchange(context.Background(), "http://gw.example.com", TokenRequest{
		GrantType:    "authorization_code",
		Code:         "gw-code",
		RedirectURI:  "cursor://anysphere.cursor-mcp/oauth/callback",
		CodeVerifier: "client-verifier",
	})
	if err != nil {
		t.Fatalf("exchange: %v", err)
	}
	got, ok := mintedSessionClaims(t, signer, resp)[identity.ClaimMCPSessionStart].(float64)
	if !ok || int64(got) != now.Unix() {
		t.Fatalf("mcp_session_start = %v, want %d", got, now.Unix())
	}
}

// A refresh renews the token, never the connection: every token refreshed
// from a session carries the login that opened it, however long ago.
func TestRefreshKeepsWhenTheClientConnected(t *testing.T) {
	t.Parallel()
	store := newMemFlowStore()
	signer := newTestSigner(t)
	proxy := NewAuthProxy(&fakeCredentialFinder{}, nil, nil, store, nil, signer, nil)
	ctx := context.Background()
	loginAt := time.Now().Add(-72 * time.Hour).UTC().Truncate(time.Second)

	const oldRefresh = "gwrt_old"
	if err := store.SaveSession(ctx, oldRefresh, SessionRecord{
		Subject:   "user-42",
		Scopes:    []string{"mcp.access"},
		GatewayID: "gw-1",
		AuthID:    "auth-1",
		LoginAt:   loginAt,
		ExpiresAt: time.Now().Add(time.Hour),
	}); err != nil {
		t.Fatalf("seed session: %v", err)
	}
	resp, err := proxy.Exchange(ctx, "http://gw.example.com", TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: oldRefresh,
	})
	if err != nil {
		t.Fatalf("refresh: %v", err)
	}
	got, ok := mintedSessionClaims(t, signer, resp)[identity.ClaimMCPSessionStart].(float64)
	if !ok || int64(got) != loginAt.Unix() {
		t.Fatalf("mcp_session_start = %v, want the login %d", got, loginAt.Unix())
	}
}
