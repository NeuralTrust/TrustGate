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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/NeuralTrust/TrustGate/pkg/common/strutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
)

var _ appoauth.UpstreamRegistrar = (*upstreamRegistrar)(nil)

// DefaultClientName is the client_name registered upstream when none is
// configured (MCP_OAUTH_CLIENT_NAME).
const DefaultClientName = "TrustGate MCP Gateway"

type upstreamRegistrar struct {
	clients    appoauth.ClientStore
	http       *http.Client
	clientName string

	mu        sync.Mutex
	discovery map[string]discoveryEntry
}

// RegistrarOption tunes NewUpstreamRegistrar.
type RegistrarOption func(*upstreamRegistrar)

// WithClientName sets the client_name sent in dynamic client registrations. A
// blank name keeps DefaultClientName. Changing the name re-registers cached
// clients (see EnsureClient), so each environment gets its own upstream app.
//
// The name is reduced to letters, digits, hyphens and spaces: some upstreams
// validate it that strictly and refuse the whole registration otherwise
// (Calendly rejects "TrustGate MCP Gateway (dev)" with invalid_client_metadata).
func WithClientName(name string) RegistrarOption {
	return func(r *upstreamRegistrar) {
		safe := portableClientName(name)
		if safe != strings.TrimSpace(name) {
			slog.Warn("oauth dcr: client name reduced to letters, digits, hyphens and spaces so strict upstreams accept it",
				"configured", name, "registered", safe)
		}
		if safe != "" {
			r.clientName = safe
		}
	}
}

// portableClientName keeps the characters every upstream seen so far accepts in
// client_name and turns any other run into a single space.
func portableClientName(name string) string {
	var b strings.Builder
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-':
			b.WriteRune(c)
		default:
			b.WriteRune(' ')
		}
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

type discoveryEntry struct {
	meta    *appoauth.UpstreamAuthServer
	expires time.Time
}

const discoveryTTL = time.Hour

func NewUpstreamRegistrar(clients appoauth.ClientStore, client *http.Client, opts ...RegistrarOption) appoauth.UpstreamRegistrar {
	if client == nil {
		client = netguard.NewHTTPClient(15 * time.Second)
	}
	r := &upstreamRegistrar{
		clients:    clients,
		http:       client,
		clientName: DefaultClientName,
		discovery:  map[string]discoveryEntry{},
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	return r
}

// clientNameMatches reports whether a cached registration carries the name this
// registrar would send. Rows written before the name was recorded count as the
// default name, so an unchanged default never churns existing registrations.
func (r *upstreamRegistrar) clientNameMatches(cached *appoauth.RegisteredClient) bool {
	if cached.ClientName == "" {
		return r.clientName == DefaultClientName
	}
	return cached.ClientName == r.clientName
}

func (r *upstreamRegistrar) Discover(ctx context.Context, upstreamURL string) (*appoauth.UpstreamAuthServer, error) {
	r.mu.Lock()
	if e, ok := r.discovery[upstreamURL]; ok && time.Now().Before(e.expires) {
		r.mu.Unlock()
		return e.meta, nil
	}
	r.mu.Unlock()

	meta, err := r.discover(ctx, upstreamURL)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	r.discovery[upstreamURL] = discoveryEntry{meta: meta, expires: time.Now().Add(discoveryTTL)}
	r.mu.Unlock()
	return meta, nil
}

func (r *upstreamRegistrar) discover(ctx context.Context, upstreamURL string) (*appoauth.UpstreamAuthServer, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("oauth dcr: bad upstream url %q", upstreamURL)
	}
	origin := u.Scheme + "://" + u.Host

	type protectedResourceMeta struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	candidates := []string{}
	if p := strings.TrimSuffix(u.Path, "/"); p != "" && p != "/" {
		candidates = append(candidates, origin+"/.well-known/oauth-protected-resource"+p)
	}
	candidates = append(candidates, origin+"/.well-known/oauth-protected-resource")
	var prm protectedResourceMeta
	found := false
	for _, c := range candidates {
		var attempt protectedResourceMeta
		if err := r.getJSON(ctx, c, &attempt); err == nil && len(attempt.AuthorizationServers) > 0 {
			prm = attempt
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("%w (%s)", appoauth.ErrUpstreamNotDiscoverable, upstreamURL)
	}

	as := strings.TrimSpace(prm.AuthorizationServers[0])
	// as is authorization_servers[0], so testing membership in that list cannot
	// fail. Refuse a value that is not an http(s) URL before it is fetched.
	if appoauth.NormalizeIssuerURL(as) == "" {
		return nil, fmt.Errorf("oauth dcr: bad authorization server %q", as)
	}
	asu, err := url.Parse(as)
	if err != nil || asu.Host == "" {
		return nil, fmt.Errorf("oauth dcr: bad authorization server %q", as)
	}
	asOrigin := asu.Scheme + "://" + asu.Host
	asPath := strings.TrimSuffix(asu.Path, "/")
	asBase := strings.TrimSuffix(as, "/")
	asCandidates := []string{
		asOrigin + "/.well-known/oauth-authorization-server" + asPath,
		asOrigin + "/.well-known/openid-configuration" + asPath,
		asBase + "/.well-known/openid-configuration",
	}
	var doc appoauth.UpstreamAuthServer
	ok := false
	mismatch := false
	for _, c := range asCandidates {
		var attempt appoauth.UpstreamAuthServer
		if err := r.getJSON(ctx, c, &attempt); err != nil || attempt.AuthorizationEndpoint == "" || attempt.TokenEndpoint == "" {
			continue
		}
		// RFC 8414 §3.3: the issuer is the URL the well-known path was inserted
		// into, not a value the document may choose. A mismatch is discarded
		// before any client secret is sent to the endpoints it names.
		if !appoauth.IssuerMatchesAuthorizationServer(attempt.Issuer, as) {
			mismatch = true
			slog.Warn("oauth dcr: discarding authorization server metadata because its issuer does not match the URL that was fetched",
				"authorization_server", appoauth.NormalizeIssuerURL(as),
				"issuer", strutil.SanitizeUpstream(attempt.Issuer, 200))
			continue
		}
		doc = attempt
		ok = true
		break
	}
	if !ok {
		if mismatch {
			return nil, fmt.Errorf("oauth dcr: authorization server issuer does not match the metadata URL")
		}
		return nil, fmt.Errorf("oauth dcr: no authorization-server metadata at %s", as)
	}
	doc.ValidatedIssuer = appoauth.NormalizeIssuerURL(as)
	doc.Issuer = doc.ValidatedIssuer
	if len(doc.ScopesSupported) == 0 {
		doc.ScopesSupported = prm.ScopesSupported
	}
	doc.Resource = prm.Resource
	if doc.Resource == "" {
		doc.Resource = upstreamURL
	}
	return &doc, nil
}

func (r *upstreamRegistrar) EnsureClient(ctx context.Context, key string, meta *appoauth.UpstreamAuthServer, redirectURI string) (*appoauth.RegisteredClient, error) {
	now := time.Now()
	cached, cacheErr := r.clients.GetClient(ctx, key)
	if cacheErr == nil && cached != nil && r.clientReusable(cached, meta, redirectURI, now) {
		return cached, nil
	}
	// A client is already registered but no longer usable here: the redirect URI
	// or client name changed, the authorization server differs, or the
	// registration expired. Replacing it is deliberate, and it invalidates every
	// refresh token the old client holds, so say so rather than losing those
	// grants silently.
	replacing := cacheErr == nil && cached != nil
	if replacing {
		newIssuer, newEndpoint := "", ""
		if meta != nil {
			newIssuer, newEndpoint = registeredIssuer(meta), meta.RegistrationEndpoint
		}
		slog.Warn("oauth dcr: re-registering upstream client because its redirect URI or client name changed; grants held by the previous client can no longer be refreshed",
			"key", key,
			"old_redirect_uri", cached.RedirectURI, "new_redirect_uri", redirectURI,
			"old_client_name", cached.ClientName, "new_client_name", r.clientName,
			"old_issuer", cached.Issuer, "new_issuer", newIssuer,
			"old_registration_endpoint", cached.RegistrationEndpoint, "new_registration_endpoint", newEndpoint,
			"registration_expired", registrationExpired(cached, now))
	}
	if meta.RegistrationEndpoint == "" {
		return nil, fmt.Errorf("%w: authorization server has no registration_endpoint", appoauth.ErrUpstreamNotDiscoverable)
	}
	body, _ := json.Marshal(map[string]any{
		"client_name":                r.clientName,
		"redirect_uris":              []string{redirectURI},
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"token_endpoint_auth_method": "none",
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, meta.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := r.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth dcr: register: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth dcr: read registration response: %w", err)
	}
	if res.StatusCode != http.StatusCreated && res.StatusCode != http.StatusOK {
		// The body is the upstream's, and the upstream is tenant-chosen: echoing
		// it would hand the caller a read channel onto whatever the registration
		// URL points at. It goes to the log; the caller gets the status and, when
		// the provider answered with a registered RFC 7591 code, that code.
		slog.Warn("oauth dcr: registration rejected by upstream",
			"status", res.StatusCode, "response", strutil.SanitizeUpstream(truncate(raw, 200), 200))
		if code := registrationErrorCode(raw); code != "" {
			return nil, fmt.Errorf("%w (status %d, %s)", appoauth.ErrUpstreamRegistrationRejected, res.StatusCode, code)
		}
		return nil, fmt.Errorf("%w (status %d)", appoauth.ErrUpstreamRegistrationRejected, res.StatusCode)
	}
	var doc struct {
		ClientID              string `json:"client_id"`
		ClientSecret          string `json:"client_secret"`
		ClientSecretExpiresAt int64  `json:"client_secret_expires_at"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.ClientID == "" {
		return nil, fmt.Errorf("oauth dcr: registration response has no client_id")
	}
	client := &appoauth.RegisteredClient{
		ClientID:              doc.ClientID,
		ClientSecret:          doc.ClientSecret,
		RedirectURI:           redirectURI,
		ClientName:            r.clientName,
		Issuer:                registeredIssuer(meta),
		RegistrationEndpoint:  meta.RegistrationEndpoint,
		ClientSecretExpiresAt: doc.ClientSecretExpiresAt,
	}
	if replacing {
		stored, swapped, err := r.clients.ReplaceClientIfMatch(ctx, key, cached.ClientID, *client)
		if err != nil {
			return nil, err
		}
		if swapped {
			return client, nil
		}
		if stored != nil && r.clientReusable(stored, meta, redirectURI, time.Now()) {
			return stored, nil
		}
		return nil, fmt.Errorf("oauth dcr: cached client changed while registering a replacement")
	}
	// First registration for this upstream. Other replicas may be registering
	// at the same moment; claim the slot atomically so all of them converge on a
	// single client_id. Overwriting here would strand the refresh tokens issued
	// to the client that lost the race, which surfaces later as invalid_grant
	// and drags the user back through consent.
	stored, err := r.clients.SaveClientIfAbsent(ctx, key, *client)
	if err != nil {
		return nil, err
	}
	if stored.ClientID != client.ClientID {
		slog.Info("oauth dcr: discarding duplicate client registration; another replica claimed this upstream first",
			"key", key, "kept_client_id", stored.ClientID)
	}
	return stored, nil
}

func (r *upstreamRegistrar) CachedClient(ctx context.Context, key string) (*appoauth.RegisteredClient, error) {
	cached, err := r.clients.GetClient(ctx, key)
	if err != nil || cached == nil || registrationExpired(cached, time.Now()) {
		return nil, err
	}
	return cached, nil
}

// rejectedRegistrationExpiry is a client_secret_expires_at in the past. Dropping
// a client stamps this on the stored row so the next EnsureClient takes the
// replacing path (and its warning) instead of deleting the slot and racing a
// fresh claim.
const rejectedRegistrationExpiry int64 = 1

// DropCachedClient marks the cached client expired when it is still clientID.
// A row that has already been replaced is left alone, so a rejection of an
// older client cannot tombstone the one a concurrent registration just stored.
// Callers that only read the cache then see no client; the next EnsureClient
// still finds the row and replaces it.
func (r *upstreamRegistrar) DropCachedClient(ctx context.Context, key, clientID string) error {
	if clientID == "" {
		return nil
	}
	cached, err := r.clients.GetClient(ctx, key)
	if err != nil || cached == nil || cached.ClientID != clientID {
		return err
	}
	cached.ClientSecretExpiresAt = rejectedRegistrationExpiry
	// The refresh marker belongs only to a redirect_uri swap. Clearing it here
	// stops a later dead-client drop of that row from posting its secret.
	cached.RefreshRetained = false
	_, _, err = r.clients.ReplaceClientIfMatch(ctx, key, clientID, *cached)
	return err
}

func (r *upstreamRegistrar) clientReusable(cached *appoauth.RegisteredClient, meta *appoauth.UpstreamAuthServer, redirectURI string, now time.Time) bool {
	return cached.RedirectURI == redirectURI &&
		r.clientNameMatches(cached) &&
		authorizationServerMatches(cached, meta) &&
		!registrationExpired(cached, now)
}

// authorizationServerMatches reports whether a cached registration was minted
// for this authorization server. A field left empty was stored before the
// binding existed and is not a mismatch: treating it as one would re-register
// every existing client and strand its refresh tokens.
func authorizationServerMatches(cached *appoauth.RegisteredClient, meta *appoauth.UpstreamAuthServer) bool {
	if meta == nil {
		return true
	}
	if cached.Issuer != "" && appoauth.NormalizeIssuerURL(cached.Issuer) != appoauth.NormalizeIssuerURL(registeredIssuer(meta)) {
		return false
	}
	if cached.RegistrationEndpoint != "" && cached.RegistrationEndpoint != meta.RegistrationEndpoint {
		return false
	}
	return true
}

func registeredIssuer(meta *appoauth.UpstreamAuthServer) string {
	if meta == nil {
		return ""
	}
	if validated := appoauth.ValidatedIssuer(meta); validated != "" {
		return validated
	}
	return appoauth.NormalizeIssuerURL(meta.Issuer)
}

func registrationExpired(cached *appoauth.RegisteredClient, now time.Time) bool {
	if cached == nil || cached.ClientSecretExpiresAt <= 0 {
		return false
	}
	return !now.Before(time.Unix(cached.ClientSecretExpiresAt, 0))
}

const (
	authorizePreflightTimeout = 3 * time.Second
	authorizePreflightMaxBody = 8 << 10
)

// PreflightAuthorize GETs rawURL once, through the same guarded client
// discovery uses, and returns that response without following a redirect.
// allowedAuthorizeURL is the catalog authorize URL. The request must be https
// and share that URL's scheme, host, and port. Anything else is refused
// before a dial.
func (r *upstreamRegistrar) PreflightAuthorize(ctx context.Context, rawURL, allowedAuthorizeURL string) (appoauth.AuthorizePreflight, error) {
	if !appoauth.AuthorizeEndpointAllowed(rawURL, allowedAuthorizeURL) {
		return appoauth.AuthorizePreflight{}, fmt.Errorf("oauth dcr: authorize preflight url is not allowed")
	}
	ctx, cancel := context.WithTimeout(ctx, authorizePreflightTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return appoauth.AuthorizePreflight{}, err
	}
	req.Header.Set("Accept", "application/json")
	client := *r.http
	client.CheckRedirect = refuseAuthorizeRedirect
	client.Timeout = authorizePreflightTimeout
	res, err := client.Do(req)
	if err != nil {
		return appoauth.AuthorizePreflight{}, err
	}
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(res.Body, authorizePreflightMaxBody))
	if err != nil {
		return appoauth.AuthorizePreflight{}, err
	}
	return appoauth.AuthorizePreflight{
		Status:   res.StatusCode,
		Location: res.Header.Get("Location"),
		Body:     string(raw),
	}, nil
}

func refuseAuthorizeRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func (r *upstreamRegistrar) getJSON(ctx context.Context, rawurl string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawurl, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	res, err := r.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", res.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, out)
}

// registrationErrorCode returns the RFC 7591 section 3.2.2 error code of a
// rejection body, or "" for anything that is not exactly one of those codes.
func registrationErrorCode(raw []byte) string {
	var doc struct {
		Error string `json:"error"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return ""
	}
	switch doc.Error {
	case "invalid_redirect_uri", "invalid_client_metadata", "invalid_software_statement", "unapproved_software_statement":
		return doc.Error
	}
	return ""
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
