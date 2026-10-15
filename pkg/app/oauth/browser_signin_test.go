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
	"errors"
	"net/url"
	"strings"
	"testing"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	oidcauth "github.com/NeuralTrust/TrustGate/pkg/infra/auth/oidc"
)

const pageReturn = "http://gw.example.com/store/mcp/personal-key/return?ticket=tk"

func browserSignInFixture(t *testing.T, claims map[string]any) *defaultIdPFixture {
	t.Helper()
	platform := newTestSigner(t)
	idp := platformIdP(t, platformToken(t, platform, claims), platform.JWKS())
	return newDefaultIdPFixture(t, idp, platform.Issuer(), "neuraltrust-mcp", WithIdPTokenVerifier(oidcauth.NewVerifier()))
}

func (f *defaultIdPFixture) browserSignIn(t *testing.T) string {
	t.Helper()
	signIn := f.proxy.(BrowserSignIn)
	loc, err := signIn.BeginBrowserSignIn(f.ctx, "http://gw.example.com", pageReturn)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatalf("parse authorize redirect: %v", err)
	}
	gw, _ := appgateway.FromContext(f.ctx)
	if u.Query().Get("gateway") != gw.ID.String() || u.Query().Get("redirect_uri") != "http://gw.example.com"+CallbackPath {
		t.Fatalf("the sign-in must go through the gateway's own callback for this gateway, got %s", loc)
	}
	back, err := f.proxy.Callback(f.ctx, "http://gw.example.com", u.Query().Get("state"), "platform-code", "", "")
	if err != nil {
		t.Fatalf("callback: %v", err)
	}
	return back
}

// The browser comes back to the page with a proof of who signed in, good once,
// and the page learns it from the verified platform token, as a Store login does.
func TestBrowserSignIn_TellsThePageWhoSignedInOnce(t *testing.T) {
	t.Parallel()
	fx := browserSignInFixture(t, map[string]any{
		"sub": "platform-user-1", "aud": "neuraltrust-mcp", "email": "ada@neuraltrust.ai",
		"org": "team-a", "groups": []string{"Eng"},
	})

	back := fx.browserSignIn(t)
	if !strings.HasPrefix(back, pageReturn+"&"+BrowserProofParam+"=") {
		t.Fatalf("the browser must come back to the page with a proof, got %s", back)
	}
	u, _ := url.Parse(back)
	proof := u.Query().Get(BrowserProofParam)
	if u.Query().Get("ticket") != "tk" {
		t.Fatalf("the page's own query must survive, got %s", back)
	}

	signIn := fx.proxy.(BrowserSignIn)
	who, err := signIn.TakeBrowserSignIn(fx.ctx, proof)
	if err != nil {
		t.Fatalf("take: %v", err)
	}
	if who.Subject != "platform-user-1" || who.Email != "ada@neuraltrust.ai" || who.Org != "team-a" || len(who.Groups) != 1 {
		t.Fatalf("identity = %+v, want the verified claims", who)
	}
	if _, err := signIn.TakeBrowserSignIn(fx.ctx, proof); !errors.Is(err, ErrBrowserProof) {
		t.Fatalf("a proof is good once, got %v", err)
	}
}

// The proof names a person; it must never become a session.
func TestBrowserSignIn_ProofIsNotACode(t *testing.T) {
	t.Parallel()
	fx := browserSignInFixture(t, map[string]any{"sub": "platform-user-1", "aud": "neuraltrust-mcp"})
	u, _ := url.Parse(fx.browserSignIn(t))

	_, err := fx.proxy.Exchange(fx.ctx, "http://gw.example.com", TokenRequest{
		GrantType:   "authorization_code",
		Code:        u.Query().Get(BrowserProofParam),
		RedirectURI: pageReturn,
	})
	var oe *OAuthError
	if !errors.As(err, &oe) || oe.Code != "invalid_grant" {
		t.Fatalf("exchanging a proof must be refused as an invalid grant, got %v", err)
	}
}

func TestBrowserSignIn_ReturnsOnlyToThisGateway(t *testing.T) {
	t.Parallel()
	fx := browserSignInFixture(t, map[string]any{"sub": "u", "aud": "neuraltrust-mcp"})
	signIn := fx.proxy.(BrowserSignIn)

	for _, returnTo := range []string{"https://evil.example/steal", "http://gw.example.com.evil/x", ""} {
		if _, err := signIn.BeginBrowserSignIn(fx.ctx, "http://gw.example.com", returnTo); err == nil {
			t.Fatalf("returnTo %q must be refused", returnTo)
		}
	}
}
