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
	"errors"
	"fmt"
	"net/url"
	"strings"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	"github.com/golang-jwt/jwt/v5"
)

// BrowserProofParam carries the one-time proof of a browser sign-in back to
// the page that asked for it.
const BrowserProofParam = "proof"

// ErrBrowserProof: the proof is unknown, used or expired, or is not one.
var ErrBrowserProof = errors.New("oauth: the sign-in could not be confirmed; start again")

// BrowserIdentity is who signed in at a browser, as the identity provider said.
type BrowserIdentity struct {
	Subject   string
	Email     string
	GatewayID string
	Org       string
	Groups    []string
}

// BrowserSignIn learns who is at a browser by sending it through the gateway's
// default identity provider, the one the MCP Store signs people in with.
//
// A page that is about to show a secret cannot take a link's word for who is
// looking at it: the link went through a model, and maybe its logs. It asks
// the browser instead. A person already signed in to the console comes straight
// back; the page then compares who came back with who the link was for.
//
// Nothing is issued: the proof names a person and is good for one look, it is
// no session and the token endpoint refuses it.
type BrowserSignIn interface {
	// BeginBrowserSignIn returns where to send the browser. returnTo, on this
	// gateway's own origin, receives the proof in BrowserProofParam.
	BeginBrowserSignIn(ctx context.Context, baseURL, returnTo string) (string, error)
	// TakeBrowserSignIn redeems a proof, once.
	TakeBrowserSignIn(ctx context.Context, proof string) (*BrowserIdentity, error)
}

var _ BrowserSignIn = (*authProxy)(nil)

func (p *authProxy) BeginBrowserSignIn(ctx context.Context, baseURL, returnTo string) (string, error) {
	base := strings.TrimRight(baseURL, "/")
	if base == "" || !strings.HasPrefix(returnTo, base+"/") {
		return "", fmt.Errorf("oauth: a browser sign-in returns to this gateway only")
	}
	gw, ok := appgateway.FromContext(ctx)
	if !ok || gw.ID.IsNil() {
		return "", oauthErr("invalid_request", "this host does not address a gateway")
	}
	auth := p.credentials.DefaultOAuth2ForGateway(gw.ID)
	if auth == nil || !appauth.IsDefaultIdP(auth) || auth.Config.OAuth2 == nil {
		return "", oauthErr("invalid_request", "this gateway has no sign-in to confirm who you are")
	}
	cfg := auth.Config.OAuth2
	ctx = netguard.TrustedIf(ctx, cfg.Trusted)
	endpoints, err := p.idp.endpoints(ctx, cfg)
	if err != nil {
		return "", err
	}
	state, err := randomToken()
	if err != nil {
		return "", err
	}
	verifier, err := randomToken()
	if err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", base+CallbackPath)
	q.Set("state", state)
	q.Set("code_challenge", s256(verifier))
	q.Set("code_challenge_method", "S256")
	if scope := upstreamScopes(cfg, ""); scope != "" {
		q.Set("scope", scope)
	}
	// The same hints a Store login sends, so the session is minted for this
	// gateway's tenant and the callback's gateway check holds.
	if tenant := gw.TenantID(); tenant != "" {
		q.Set("org", tenant)
	}
	q.Set("gateway", gw.ID.String())
	pending := PendingAuthorization{
		RedirectURI:         returnTo,
		CodeChallengeMethod: "S256",
		CodeVerifier:        verifier,
		Resource:            base + "/" + consumerdomain.StoreSlug + "/mcp",
		AuthID:              auth.ID.String(),
		GatewayID:           gw.ID.String(),
		AuthorizeURL:        endpoints.authorize + "?" + q.Encode(),
		// The page that started it is the gateway's own: there is no third-party
		// client to approve.
		Approved:      true,
		BrowserSignIn: true,
	}
	if err := p.store.SavePending(ctx, state, pending); err != nil {
		return "", fmt.Errorf("oauth: park browser sign-in: %w", err)
	}
	return pending.AuthorizeURL, nil
}

// finishBrowserSignIn is the end of Callback for a browser sign-in: the token
// is verified by then; what is left is to say who it was for, once.
func (p *authProxy) finishBrowserSignIn(
	ctx context.Context,
	pending *PendingAuthorization,
	auth *authdomain.Auth,
	verified map[string]any,
	token map[string]any,
	gatewayID string,
) (string, error) {
	cfg := auth.Config.OAuth2
	grant := CodeGrant{RedirectURI: pending.RedirectURI, GatewayID: gatewayID, BrowserSignIn: true}
	if verified != nil {
		grant.Subject = subjectFromClaims(jwt.MapClaims(verified), cfg.SubjectClaim)
		grant.Email = identity.EmailFromClaims(verified)
		grant.Org = orgFromClaims(verified)
		grant.Groups = groupsFromClaims(verified)
	} else {
		sub, err := p.captureSubject(ctx, cfg, token)
		if err != nil {
			return "", err
		}
		grant.Subject = sub
		grant.Email = emailFromToken(token)
		grant.Org = orgFromToken(token)
		grant.Groups = groupsFromToken(token)
	}
	if grant.Subject == "" {
		return "", oauthErr("access_denied", "could not determine subject from identity provider")
	}
	proof, err := randomToken()
	if err != nil {
		return "", err
	}
	if err := p.store.SaveCode(ctx, proof, grant); err != nil {
		return "", fmt.Errorf("oauth: store browser sign-in: %w", err)
	}
	return clientRedirect(pending.RedirectURI, url.Values{BrowserProofParam: {proof}}, ""), nil
}

func (p *authProxy) TakeBrowserSignIn(ctx context.Context, proof string) (*BrowserIdentity, error) {
	if strings.TrimSpace(proof) == "" {
		return nil, ErrBrowserProof
	}
	grant, err := p.store.TakeCode(ctx, proof)
	if err != nil {
		return nil, fmt.Errorf("oauth: load browser sign-in: %w", err)
	}
	if grant == nil || !grant.BrowserSignIn || grant.Subject == "" {
		return nil, ErrBrowserProof
	}
	return &BrowserIdentity{
		Subject:   grant.Subject,
		Email:     grant.Email,
		GatewayID: grant.GatewayID,
		Org:       grant.Org,
		Groups:    grant.Groups,
	}, nil
}
