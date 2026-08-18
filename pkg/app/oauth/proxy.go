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
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appsts "github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/golang-jwt/jwt/v5"
)

var _ AuthProxy = (*authProxy)(nil)

type authProxy struct {
	credentials appauth.CredentialFinder
	paths       appconsumer.PathResolver
	store       FlowStore
	idp         *idpTransport
	chainer     ConsentChainer
	signer      appsts.TokenSigner
	userinfo    UserInfoClient
	verifier    appauth.OIDCVerifier
}

func NewAuthProxy(
	credentials appauth.CredentialFinder,
	paths appconsumer.PathResolver,
	client *http.Client,
	store FlowStore,
	chainer ConsentChainer,
	signer appsts.TokenSigner,
	userinfo UserInfoClient,
	verifier appauth.OIDCVerifier,
) AuthProxy {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	meta := &metadataService{credentials: credentials, client: client, asCache: map[string]asCacheEntry{}}
	return &authProxy{
		credentials: credentials,
		paths:       paths,
		store:       store,
		idp:         newIDPTransport(client, meta),
		chainer:     chainer,
		signer:      signer,
		userinfo:    userinfo,
		verifier:    verifier,
	}
}

func (p *authProxy) Authorize(ctx context.Context, baseURL string, req AuthorizeRequest) (string, error) {
	if req.ResponseType != "code" {
		return "", oauthErr("unsupported_response_type", "only response_type=code is supported")
	}
	if req.RedirectURI == "" {
		return "", oauthErr("invalid_request", "redirect_uri is required")
	}
	if req.CodeChallenge == "" || (req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "S256") {
		return "", oauthErr("invalid_request", "PKCE with code_challenge_method=S256 is required")
	}
	// The redirect_uri is only trustworthy once it has been checked against the
	// client, so that check comes before anything else that can fail: from here
	// on a protocol error can be reported to the client instead of rendered
	// here, where an agent waiting on its callback would never read it.
	if err := p.validateClientRedirect(ctx, req.ClientID, req.RedirectURI); err != nil {
		return "", err
	}
	auth, err := p.authForResource(ctx, req.Resource)
	if err != nil {
		return authorizeFailure(baseURL, req, err)
	}
	cfg := auth.Config.OAuth2
	if cfg != nil && cfg.EffectiveNorthboundMode() == authdomain.NorthboundModeEMA {
		return authorizeFailure(baseURL, req, oauthErr("access_denied", "authorization code flow is disabled for this identity provider"))
	}
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
	pending := PendingAuthorization{
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		State:               req.State,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: "S256",
		Scope:               req.Scope,
		CodeVerifier:        verifier,
		Resource:            req.Resource,
		AuthID:              auth.ID.String(),
		GatewayID:           auth.GatewayID.String(),
		Issuer:              endpoints.issuer,
		IssAdvertised:       endpoints.advertised,
	}
	if err := p.store.SavePending(ctx, state, pending); err != nil {
		return "", fmt.Errorf("oauth: park authorization: %w", err)
	}

	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", baseURL+CallbackPath)
	q.Set("state", state)
	q.Set("code_challenge", s256(verifier))
	q.Set("code_challenge_method", "S256")
	if scope := mergeScopes(req.Scope, cfg.RequiredScopes); scope != "" {
		q.Set("scope", scope)
	}
	return endpoints.authorize + "?" + q.Encode(), nil
}

// authorizeFailure turns a rejected authorization into a redirect back to the
// client, as RFC 6749 §4.1.2.1 requires once the redirect_uri is validated.
// Anything that is not a protocol error is a fault on this side and is left to
// the caller to render.
func authorizeFailure(baseURL string, req AuthorizeRequest, err error) (string, error) {
	var oe *OAuthError
	if !errors.As(err, &oe) {
		return "", err
	}
	return clientRedirect(req.RedirectURI, url.Values{
		"error":             {oe.Code},
		"error_description": {oe.Description},
		"iss":               {baseURL},
	}, req.State), nil
}

func (p *authProxy) Callback(ctx context.Context, baseURL, state, code, idpErr, idpErrDesc, iss string) (string, error) {
	pending, err := p.store.TakePending(ctx, state)
	if err != nil {
		return "", fmt.Errorf("oauth: load pending authorization: %w", err)
	}
	if pending == nil {
		return "", oauthErr("invalid_request", "unknown or expired authorization request")
	}
	if idpErr != "" {
		return clientRedirect(pending.RedirectURI, url.Values{
			"error":             {idpErr},
			"error_description": {idpErrDesc},
			"iss":               {baseURL},
		}, pending.State), nil
	}
	if err := validateResponseISS(iss, pending.Issuer, pending.IssAdvertised); err != nil {
		logIssuerMismatch(pending.Issuer, iss, pending.GatewayID, "", "")
		return "", err
	}

	auth, err := p.pendingAuth(ctx, pending)
	if err != nil {
		return "", err
	}
	cfg := auth.Config.OAuth2
	// The built-in default identity provider is platform-wide and carries no
	// gateway of its own (its auth record is a shared singleton, so it must not
	// be mutated); the addressed gateway was captured at authorize time. Resolve
	// it once here for both the minted session and the consent detour.
	effectiveGatewayID := auth.GatewayID
	if pending.GatewayID != "" {
		if gw, perr := ids.Parse[ids.GatewayKind](pending.GatewayID); perr == nil {
			effectiveGatewayID = gw
		}
	}
	endpoints, err := p.idp.endpoints(ctx, cfg)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", baseURL+CallbackPath)
	form.Set("client_id", cfg.ClientID)
	form.Set("code_verifier", pending.CodeVerifier)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	token, err := p.idp.tokenCall(ctx, endpoints.token, form)
	if err != nil {
		return "", err
	}

	gwCode, err := randomToken()
	if err != nil {
		return "", err
	}
	grant := CodeGrant{
		ClientID:      pending.ClientID,
		RedirectURI:   pending.RedirectURI,
		CodeChallenge: pending.CodeChallenge,
		Token:         token,
	}
	var capturedSubject string
	if cfg.SessionMode {
		sub, captureErr := p.captureSubject(ctx, cfg, token)
		if captureErr != nil {
			return "", captureErr
		}
		if sub == "" {
			return "", oauthErr("access_denied", "could not determine subject from identity provider")
		}
		capturedSubject = sub
		grant.Subject = sub
		grant.AuthID = auth.ID.String()
		grant.GatewayID = effectiveGatewayID.String()
		grant.Audiences = cfg.Audiences
		grant.Scopes = grantedScopes(token, pending.Scope)
		grant.SessionMode = true
	}
	if err := p.store.SaveCode(ctx, gwCode, grant); err != nil {
		return "", fmt.Errorf("oauth: store code grant: %w", err)
	}
	resume := clientRedirect(pending.RedirectURI, url.Values{"code": {gwCode}, "iss": {baseURL}}, pending.State)
	if detour := p.consentDetour(ctx, baseURL, effectiveGatewayID, pending.Resource, capturedSubject, token, resume); detour != "" {
		return detour, nil
	}
	return resume, nil
}

func (p *authProxy) consentDetour(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, subject string, token map[string]any, resume string) string {
	if p.chainer == nil {
		return ""
	}
	sub := subject
	if sub == "" {
		sub = subjectFromToken(token)
	}
	if sub == "" {
		slog.Warn("oauth: consent chaining skipped: no subject in IdP access token")
		return ""
	}
	detour, err := p.chainer.ChainURL(ctx, baseURL, gatewayID, resource, sub, resume)
	if err != nil {
		slog.Warn("oauth: consent chaining skipped", "error", err)
		return ""
	}
	if detour != "" {
		slog.Info("oauth: detouring to downstream consent page", "sub", sub, "resource", resource)
	}
	return detour
}

func subjectFromToken(token map[string]any) string {
	raw, _ := token["access_token"].(string)
	if raw == "" {
		return ""
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
		return ""
	}
	if oid, ok := claims["oid"].(string); ok && oid != "" {
		return oid
	}
	sub, _ := claims.GetSubject()
	return sub
}

func (p *authProxy) captureSubject(ctx context.Context, cfg *authdomain.OAuth2Config, token map[string]any) (string, error) {
	if raw, ok := token["id_token"].(string); ok && raw != "" {
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(raw, claims); err != nil {
			return "", fmt.Errorf("oauth: parse id_token: %w", err)
		}
		return subjectFromClaims(claims, cfg.SubjectClaim), nil
	}
	if cfg.UserInfoURL != "" {
		accessToken, _ := token["access_token"].(string)
		info, err := p.userinfo.Fetch(ctx, cfg.UserInfoURL, accessToken)
		if err != nil {
			return "", fmt.Errorf("oauth: fetch userinfo: %w", err)
		}
		claim := cfg.SubjectClaim
		if claim == "" {
			claim = "sub"
		}
		return coerceClaim(info[claim]), nil
	}
	return subjectFromToken(token), nil
}

func subjectFromClaims(claims jwt.MapClaims, claim string) string {
	if claim != "" {
		return coerceClaim(claims[claim])
	}
	if oid := coerceClaim(claims["oid"]); oid != "" {
		return oid
	}
	return coerceClaim(claims["sub"])
}

func coerceClaim(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case json.Number:
		return t.String()
	case float64:
		return formatNumericClaim(t)
	case float32:
		return formatNumericClaim(float64(t))
	case int:
		return strconv.FormatInt(int64(t), 10)
	case int64:
		return strconv.FormatInt(t, 10)
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprintf("%v", v)
	}
}

func formatNumericClaim(f float64) string {
	if !math.IsInf(f, 0) && !math.IsNaN(f) && f == math.Trunc(f) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'f', -1, 64)
}

func grantedScopes(token map[string]any, requested string) []string {
	if scope, ok := token["scope"].(string); ok && scope != "" {
		return strings.Fields(scope)
	}
	return strings.Fields(requested)
}

func (p *authProxy) Exchange(ctx context.Context, baseURL string, req TokenRequest) (map[string]any, error) {
	switch req.GrantType {
	case "authorization_code":
		return p.exchangeCode(ctx, req)
	case "refresh_token":
		return p.refresh(ctx, req)
	case grantJWTBearer:
		return p.exchangeJWTBearer(ctx, baseURL, req)
	default:
		return nil, oauthErr("unsupported_grant_type", "supported: authorization_code, refresh_token")
	}
}

func (p *authProxy) exchangeJWTBearer(ctx context.Context, baseURL string, req TokenRequest) (map[string]any, error) {
	if strings.TrimSpace(req.Assertion) == "" {
		return nil, oauthErr("invalid_request", "assertion is required")
	}
	auth, err := p.authForResource(ctx, req.Resource)
	if err != nil {
		return nil, err
	}
	cfg := auth.Config.OAuth2
	if cfg == nil || cfg.EffectiveNorthboundMode() == authdomain.NorthboundModeOIDC {
		return nil, oauthErr("unsupported_grant_type", "supported: authorization_code, refresh_token")
	}
	if req.ClientID == "" {
		return nil, oauthErr("invalid_client", "client_id is required")
	}
	if p.store == nil {
		logEMADeny(auth.ID.String(), auth.GatewayID.String(), "store")
		return nil, oauthErr("invalid_grant", "invalid assertion")
	}
	client, err := p.store.GetGatewayClient(ctx, req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("oauth: load client registration: %w", err)
	}
	if client == nil {
		return nil, oauthErr("invalid_client", "unknown client_id; register via /oauth/register")
	}
	jag, err := p.validateIDJAG(ctx, baseURL, auth, req)
	if err != nil {
		return nil, err
	}
	if err := p.store.ConsumeJTI(ctx, jag.jti, jag.exp); err != nil {
		logEMADeny(auth.ID.String(), auth.GatewayID.String(), "jti")
		return nil, oauthErr("invalid_grant", "invalid assertion")
	}
	grant := CodeGrant{
		ClientID:    req.ClientID,
		Subject:     jag.subject,
		AuthID:      auth.ID.String(),
		GatewayID:   auth.GatewayID.String(),
		Audiences:   cfg.Audiences,
		Scopes:      jag.scopes,
		SessionMode: true,
		Claims:      jag.claims,
	}
	resp, err := p.mintSession(grant)
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	refresh := gatewayRefreshPrefix + token
	rec := SessionRecord{
		Subject:   grant.Subject,
		Scopes:    grant.Scopes,
		GatewayID: grant.GatewayID,
		AuthID:    grant.AuthID,
		Audiences: grant.Audiences,
	}
	if err := p.store.SaveSession(ctx, refresh, rec); err != nil {
		return nil, fmt.Errorf("oauth: persist session: %w", err)
	}
	resp["refresh_token"] = refresh
	return resp, nil
}

func (p *authProxy) exchangeCode(ctx context.Context, req TokenRequest) (map[string]any, error) {
	if req.Code == "" {
		return nil, oauthErr("invalid_request", "code is required")
	}
	grant, err := p.store.TakeCode(ctx, req.Code)
	if err != nil {
		return nil, fmt.Errorf("oauth: load code grant: %w", err)
	}
	if grant == nil {
		return nil, oauthErr("invalid_grant", "unknown, expired or already used code")
	}
	if grant.RedirectURI != req.RedirectURI {
		return nil, oauthErr("invalid_grant", "redirect_uri mismatch")
	}
	if grant.ClientID != "" && req.ClientID != "" && grant.ClientID != req.ClientID {
		return nil, oauthErr("invalid_client", "client_id mismatch")
	}
	if req.CodeVerifier == "" || s256(req.CodeVerifier) != grant.CodeChallenge {
		return nil, oauthErr("invalid_grant", "PKCE verification failed")
	}
	if grant.SessionMode {
		resp, err := p.mintSession(*grant)
		if err != nil {
			return nil, err
		}
		token, err := randomToken()
		if err != nil {
			return nil, err
		}
		refresh := gatewayRefreshPrefix + token
		rec := SessionRecord{
			Subject:   grant.Subject,
			Scopes:    grant.Scopes,
			GatewayID: grant.GatewayID,
			AuthID:    grant.AuthID,
			Audiences: grant.Audiences,
		}
		if err := p.store.SaveSession(ctx, refresh, rec); err != nil {
			return nil, fmt.Errorf("oauth: persist session: %w", err)
		}
		resp["refresh_token"] = refresh
		return resp, nil
	}
	return grant.Token, nil
}

func (p *authProxy) mintSession(grant CodeGrant) (map[string]any, error) {
	claims := jwt.MapClaims{}
	for k, v := range grant.Claims {
		switch k {
		case "act", "jti", "client_id":
			continue
		default:
			claims[k] = v
		}
	}
	claims["sub"] = grant.Subject
	claims["scope"] = strings.Join(grant.Scopes, " ")
	claims["authid"] = grant.AuthID
	claims["token_use"] = "mcp_session"
	// gwid binds the session to the gateway the login was brokered for. It is
	// authoritative for the built-in default identity provider, whose synthetic
	// auth record carries no gateway of its own.
	if grant.GatewayID != "" {
		claims["gwid"] = grant.GatewayID
	}
	if len(grant.Audiences) > 0 {
		claims["aud"] = grant.Audiences
	}
	signed, err := p.signer.MintClaims(claims, time.Hour)
	if err != nil {
		return nil, fmt.Errorf("oauth: mint session token: %w", err)
	}
	return map[string]any{
		"access_token": signed,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(grant.Scopes, " "),
	}, nil
}

// sessionRotationGrace is how long a rotated gateway refresh token stays
// usable after a successful refresh. Long enough to absorb a client's
// concurrent workers and transport retries, short enough that a leaked old
// token is worthless minutes later.
const sessionRotationGrace = 60 * time.Second

func (p *authProxy) refresh(ctx context.Context, req TokenRequest) (map[string]any, error) {
	if req.RefreshToken == "" {
		return nil, oauthErr("invalid_request", "refresh_token is required")
	}
	if strings.HasPrefix(req.RefreshToken, gatewayRefreshPrefix) {
		rec, err := p.store.GetSession(ctx, req.RefreshToken)
		if err != nil {
			return nil, fmt.Errorf("oauth: load session: %w", err)
		}
		if rec == nil {
			return nil, oauthErr("invalid_grant", "unknown or expired refresh token")
		}
		resp, err := p.refreshSession(ctx, *rec)
		if err != nil {
			return nil, err
		}
		// Rotate with a grace window rather than single-use: the old token keeps
		// working for a short overlap so a concurrent worker of the same client,
		// or a retry after a lost token response, still lands on a valid grant
		// instead of invalid_grant (which clients treat as session death).
		if err := p.store.RetireSession(ctx, req.RefreshToken, sessionRotationGrace); err != nil {
			return nil, fmt.Errorf("oauth: retire rotated refresh token: %w", err)
		}
		return resp, nil
	}
	auth, err := p.authForResource(ctx, req.Resource)
	if err != nil {
		return nil, err
	}
	cfg := auth.Config.OAuth2
	endpoints, err := p.idp.endpoints(ctx, cfg)
	if err != nil {
		return nil, err
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", req.RefreshToken)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	if scope := mergeScopes("", cfg.RequiredScopes); scope != "" {
		form.Set("scope", scope)
	}
	return p.idp.tokenCall(ctx, endpoints.token, form)
}

func (p *authProxy) refreshSession(ctx context.Context, rec SessionRecord) (map[string]any, error) {
	resp, err := p.mintSession(CodeGrant{
		Subject:   rec.Subject,
		Scopes:    rec.Scopes,
		AuthID:    rec.AuthID,
		GatewayID: rec.GatewayID,
		Audiences: rec.Audiences,
	})
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	newRefresh := gatewayRefreshPrefix + token
	if err := p.store.SaveSession(ctx, newRefresh, rec); err != nil {
		return nil, fmt.Errorf("oauth: rotate session: %w", err)
	}
	resp["refresh_token"] = newRefresh
	return resp, nil
}
