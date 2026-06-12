package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	"github.com/golang-jwt/jwt/v5"
)

// The gateway is the OAuth 2.1 Authorization Server facade for MCP clients:
// clients register via DCR and run authorize/token against the gateway, while
// the gateway is the only OAuth client registered at the corporate IdP, with
// one stable redirect URI ({gateway}/oauth/callback). This decouples client
// callbacks (cursor://..., random loopback ports) from IdP app registrations.

// CallbackPath is the gateway's stable redirect URI path registered at the IdP.
const CallbackPath = "/oauth/callback"

// OAuthError is an RFC 6749 error response (error + optional description).
type OAuthError struct {
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

func (e *OAuthError) Error() string {
	if e.Description == "" {
		return e.Code
	}
	return e.Code + ": " + e.Description
}

func oauthErr(code, desc string) *OAuthError { return &OAuthError{Code: code, Description: desc} }

// PendingAuthorization is the client's authorize request, parked while the
// user authenticates at the IdP. Keyed by the state the gateway sends to the IdP.
type PendingAuthorization struct {
	ClientID            string `json:"client_id"`
	RedirectURI         string `json:"redirect_uri"`
	State               string `json:"state"`
	CodeChallenge       string `json:"code_challenge"`
	CodeChallengeMethod string `json:"code_challenge_method"`
	Scope               string `json:"scope"`
	IDPVerifier         string `json:"idp_verifier"`
	// Resource is the RFC 8707 resource indicator from the client's authorize
	// request (the virtual MCP URL). It lets the callback chain the downstream
	// consent UI for that consumer right after the IdP leg.
	Resource string `json:"resource,omitempty"`
	// AuthID pins the oauth2 Auth entry selected at authorize time (by the
	// resource indicator), so the callback leg talks to the same IdP even
	// when several are configured.
	AuthID string `json:"auth_id,omitempty"`
}

// CodeGrant binds a gateway-minted authorization code to the client's PKCE
// challenge and the IdP token response it unlocks.
type CodeGrant struct {
	ClientID      string         `json:"client_id"`
	RedirectURI   string         `json:"redirect_uri"`
	CodeChallenge string         `json:"code_challenge"`
	Token         map[string]any `json:"token"`
}

// FlowStore persists short-lived authorization flow state (Redis-backed) so
// any gateway replica can serve any leg of the flow. Take semantics are
// single-use: the entry is deleted on read.
type FlowStore interface {
	SavePending(ctx context.Context, state string, p PendingAuthorization) error
	TakePending(ctx context.Context, state string) (*PendingAuthorization, error)
	SaveCode(ctx context.Context, code string, g CodeGrant) error
	TakeCode(ctx context.Context, code string) (*CodeGrant, error)
}

// AuthorizeRequest is the client leg of /oauth/authorize.
type AuthorizeRequest struct {
	ResponseType        string
	ClientID            string
	RedirectURI         string
	State               string
	Scope               string
	CodeChallenge       string
	CodeChallengeMethod string
	Resource            string
}

// TokenRequest is the client leg of /oauth/token.
type TokenRequest struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	CodeVerifier string
	RefreshToken string
	// Resource is the RFC 8707 resource indicator; on refresh_token grants
	// it selects the IdP behind the addressed virtual MCP.
	Resource string
}

// ConsentChainer inserts the downstream consent UI into the inbound OAuth
// flow: right after the IdP leg it can park the client redirect and send the
// user to the connect page for any forwarded providers they have not linked
// yet. Implemented by the ConnectService.
type ConsentChainer interface {
	// ChainURL returns the connect-page URL when the principal still has
	// unlinked forwarded providers behind the resource, or "" to proceed
	// directly with resumeURL (the client redirect carrying the code).
	ChainURL(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource, principalSub, resumeURL string) (string, error)
}

type AuthProxy interface {
	// Authorize parks the client request and returns the IdP authorization URL.
	Authorize(ctx context.Context, baseURL string, req AuthorizeRequest) (string, error)
	// Callback exchanges the IdP code, mints a gateway code, and returns the
	// client redirect URL. idpErr propagates IdP-denied flows to the client.
	Callback(ctx context.Context, baseURL, state, code, idpErr, idpErrDesc string) (string, error)
	// Exchange serves the client token request (authorization_code with PKCE,
	// or refresh_token proxied to the IdP).
	Exchange(ctx context.Context, baseURL string, req TokenRequest) (map[string]any, error)
}

var _ AuthProxy = (*authProxy)(nil)

type authProxy struct {
	credentials appauth.CredentialFinder
	paths       appconsumer.PathResolver
	client      *http.Client
	store       FlowStore
	idp         *metadataService
	chainer     ConsentChainer
}

func NewAuthProxy(
	credentials appauth.CredentialFinder,
	paths appconsumer.PathResolver,
	client *http.Client,
	store FlowStore,
	chainer ConsentChainer,
) AuthProxy {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &authProxy{
		credentials: credentials,
		paths:       paths,
		client:      client,
		store:       store,
		idp:         &metadataService{credentials: credentials, client: client, asCache: map[string]asCacheEntry{}},
		chainer:     chainer,
	}
}

func (p *authProxy) Authorize(ctx context.Context, baseURL string, req AuthorizeRequest) (string, error) {
	if req.ResponseType != "code" {
		return "", oauthErr("unsupported_response_type", "only response_type=code is supported")
	}
	if req.RedirectURI == "" {
		return "", oauthErr("invalid_request", "redirect_uri is required")
	}
	// OAuth 2.1: PKCE is mandatory for public clients.
	if req.CodeChallenge == "" || (req.CodeChallengeMethod != "" && req.CodeChallengeMethod != "S256") {
		return "", oauthErr("invalid_request", "PKCE with code_challenge_method=S256 is required")
	}
	auth, err := p.authForResource(ctx, req.Resource)
	if err != nil {
		return "", err
	}
	cfg := auth.Config.OAuth2
	if !p.knownClientID(ctx, req.ClientID) {
		return "", oauthErr("invalid_client", "unknown client_id; register via /oauth/register")
	}
	endpoints, err := p.idpEndpoints(ctx, cfg.Issuer)
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
		IDPVerifier:         verifier,
		Resource:            req.Resource,
		AuthID:              auth.ID.String(),
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

func (p *authProxy) Callback(ctx context.Context, baseURL, state, code, idpErr, idpErrDesc string) (string, error) {
	pending, err := p.store.TakePending(ctx, state)
	if err != nil {
		return "", fmt.Errorf("oauth: load pending authorization: %w", err)
	}
	if pending == nil {
		return "", oauthErr("invalid_request", "unknown or expired authorization request")
	}
	if idpErr != "" {
		// The IdP denied the flow (e.g. user cancelled consent): relay to the client.
		return clientRedirect(pending.RedirectURI, url.Values{
			"error":             {idpErr},
			"error_description": {idpErrDesc},
		}, pending.State), nil
	}

	auth, err := p.pendingAuth(ctx, pending)
	if err != nil {
		return "", err
	}
	cfg := auth.Config.OAuth2
	endpoints, err := p.idpEndpoints(ctx, cfg.Issuer)
	if err != nil {
		return "", err
	}

	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", baseURL+CallbackPath)
	form.Set("client_id", cfg.ClientID)
	form.Set("code_verifier", pending.IDPVerifier)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	token, err := p.idpTokenCall(ctx, endpoints.token, form)
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
	if err := p.store.SaveCode(ctx, gwCode, grant); err != nil {
		return "", fmt.Errorf("oauth: store code grant: %w", err)
	}
	resume := clientRedirect(pending.RedirectURI, url.Values{"code": {gwCode}}, pending.State)
	if detour := p.consentDetour(ctx, baseURL, auth.GatewayID, pending.Resource, token, resume); detour != "" {
		return detour, nil
	}
	return resume, nil
}

// consentDetour decides whether the downstream consent UI should interrupt
// the flow: with the user already in the browser, surface the provider links
// (Connect Linear, ...) before handing the code back to the client.
// Best-effort: any failure falls through to the normal redirect.
func (p *authProxy) consentDetour(ctx context.Context, baseURL string, gatewayID ids.GatewayID, resource string, token map[string]any, resume string) string {
	if p.chainer == nil {
		return ""
	}
	sub := subjectFromToken(token)
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

// subjectFromToken extracts the principal subject from the IdP access token,
// preferring the stable object id (Entra oid). The token comes straight from
// the IdP token endpoint over TLS, so it is parsed without re-verification.
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

func (p *authProxy) Exchange(ctx context.Context, baseURL string, req TokenRequest) (map[string]any, error) {
	switch req.GrantType {
	case "authorization_code":
		return p.exchangeCode(ctx, req)
	case "refresh_token":
		return p.refresh(ctx, req)
	default:
		return nil, oauthErr("unsupported_grant_type", "supported: authorization_code, refresh_token")
	}
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
	return grant.Token, nil
}

func (p *authProxy) refresh(ctx context.Context, req TokenRequest) (map[string]any, error) {
	if req.RefreshToken == "" {
		return nil, oauthErr("invalid_request", "refresh_token is required")
	}
	auth, err := p.authForResource(ctx, req.Resource)
	if err != nil {
		return nil, err
	}
	cfg := auth.Config.OAuth2
	endpoints, err := p.idpEndpoints(ctx, cfg.Issuer)
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
	return p.idpTokenCall(ctx, endpoints.token, form)
}

type idpEndpoints struct {
	authorize string
	token     string
}

func (p *authProxy) idpEndpoints(ctx context.Context, issuer string) (*idpEndpoints, error) {
	doc, err := p.idp.fetchASMetadata(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("oauth: resolve IdP endpoints: %w", err)
	}
	authorize, _ := doc["authorization_endpoint"].(string)
	token, _ := doc["token_endpoint"].(string)
	if authorize == "" || token == "" {
		return nil, fmt.Errorf("oauth: IdP metadata for %s lacks authorization/token endpoints", issuer)
	}
	return &idpEndpoints{authorize: authorize, token: token}, nil
}

// idpTokenCall posts the form to the IdP token endpoint and returns the JSON
// body. IdP OAuth errors are propagated as OAuthError.
func (p *authProxy) idpTokenCall(ctx context.Context, endpoint string, form url.Values) (map[string]any, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := p.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("oauth: IdP token call: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth: read IdP token response: %w", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oauth: IdP token response is not JSON (status %d)", res.StatusCode)
	}
	if res.StatusCode != http.StatusOK {
		code, _ := doc["error"].(string)
		desc, _ := doc["error_description"].(string)
		if code == "" {
			code = "server_error"
		}
		return nil, oauthErr(code, desc)
	}
	return doc, nil
}

// authForResource selects the oauth2 Auth entry behind a facade request.
// Resource-scoped (RFC 8707): the resource URL is resolved path-first to a
// consumer and its attached oauth2 auth wins. Without a resolvable resource
// the single-issuer fallback keeps single-IdP deployments working; with
// several issuers the client must say which MCP server it is talking to.
func (p *authProxy) authForResource(ctx context.Context, resource string) (*authdomain.Auth, error) {
	if a := p.resourceAuth(ctx, resource); a != nil {
		return a, nil
	}
	a, err := p.singleOAuth2Auth(ctx)
	if errors.Is(err, ErrAmbiguousAuthorizationServer) {
		return nil, oauthErr("invalid_target",
			"multiple identity providers configured; send an RFC 8707 resource parameter identifying the MCP server")
	}
	return a, err
}

// resourceAuth resolves the RFC 8707 resource URL to the addressed consumer's
// enabled oauth2 Auth entry, or nil when it cannot (best-effort selector).
func (p *authProxy) resourceAuth(ctx context.Context, resource string) *authdomain.Auth {
	if p.paths == nil || resource == "" {
		return nil
	}
	u, err := url.Parse(resource)
	if err != nil || u.Path == "" {
		return nil
	}
	matches, err := p.paths.Match(ctx, u.Host, u.Path)
	if err != nil {
		slog.Warn("oauth: resource lookup failed; falling back to single-issuer selection",
			"resource", resource, "error", err)
		return nil
	}
	for _, m := range matches {
		for _, a := range m.Auths {
			if a.Enabled && a.Type == authdomain.TypeOAuth2 && a.Config.OAuth2 != nil {
				return a
			}
		}
	}
	return nil
}

// pendingAuth recovers the Auth entry pinned at authorize time; pendings
// minted before the pin existed fall back to resource/single selection.
func (p *authProxy) pendingAuth(ctx context.Context, pending *PendingAuthorization) (*authdomain.Auth, error) {
	if pending.AuthID != "" {
		auths, err := p.credentials.OAuth2Auths(ctx)
		if err != nil {
			return nil, fmt.Errorf("oauth: load oauth2 auths: %w", err)
		}
		for _, a := range auths {
			if a.ID.String() == pending.AuthID {
				return a, nil
			}
		}
		return nil, oauthErr("invalid_request", "the identity provider behind this authorization is no longer configured")
	}
	return p.authForResource(ctx, pending.Resource)
}

// knownClientID accepts a client_id handed out by DCR (any configured IdP
// client). An empty client_id is allowed: the gateway is a facade and the
// real client at the IdP is always the admin-registered one; PKCE binds the
// flow to the requesting client.
func (p *authProxy) knownClientID(ctx context.Context, clientID string) bool {
	if clientID == "" {
		return true
	}
	auths, err := p.credentials.OAuth2Auths(ctx)
	if err != nil {
		return false
	}
	configured := false
	for _, a := range auths {
		cfg := a.Config.OAuth2
		if cfg == nil || cfg.ClientID == "" {
			continue
		}
		configured = true
		if cfg.ClientID == clientID {
			return true
		}
	}
	// No entry declares a client id: nothing to match against, accept.
	return !configured
}

func (p *authProxy) singleOAuth2Auth(ctx context.Context) (*authdomain.Auth, error) {
	auths, err := p.credentials.OAuth2Auths(ctx)
	if err != nil {
		return nil, fmt.Errorf("oauth: load oauth2 auths: %w", err)
	}
	issuers := issuersOf(auths)
	if len(issuers) == 0 {
		return nil, ErrNoAuthorizationServer
	}
	if len(issuers) > 1 {
		return nil, ErrAmbiguousAuthorizationServer
	}
	for _, a := range auths {
		if a.Config.OAuth2 != nil && a.Config.OAuth2.Issuer == issuers[0] {
			return a, nil
		}
	}
	return nil, ErrNoAuthorizationServer
}

func clientRedirect(redirectURI string, params url.Values, state string) string {
	if state != "" {
		params.Set("state", state)
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return redirectURI + sep + params.Encode()
}

// mergeScopes unions the client-requested scopes with the configured required
// scopes, so the IdP issues a token the gateway will accept.
func mergeScopes(requested string, required []string) string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range append(strings.Fields(requested), required...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("oauth: entropy unavailable")
	}
	return hex.EncodeToString(buf), nil
}
