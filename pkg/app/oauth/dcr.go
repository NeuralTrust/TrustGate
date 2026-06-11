package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Auto client registration (forwarded mode, registration: auto): the gateway
// acts as a standard MCP/OAuth client toward the upstream. It discovers the
// upstream's authorization server through RFC 9728 protected-resource
// metadata, then registers itself via RFC 7591 Dynamic Client Registration -
// so onboarding a spec-compliant SaaS MCP (Linear, Notion, ...) needs no
// pre-registered OAuth app and no client secret in config.

// ErrUpstreamNotDiscoverable: the upstream does not publish MCP authorization
// metadata; the admin must fall back to manual registration.
var ErrUpstreamNotDiscoverable = errors.New(
	"oauth dcr: upstream does not publish OAuth protected-resource metadata; configure registration: manual with a pre-registered OAuth app")

// UpstreamAuthServer is the discovered authorization-server surface of one
// upstream MCP server.
type UpstreamAuthServer struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	RegistrationEndpoint  string   `json:"registration_endpoint"`
	ScopesSupported       []string `json:"scopes_supported"`
	Resource              string   `json:"resource"`
}

// RegisteredClient is the gateway's DCR-issued client at one upstream.
type RegisteredClient struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret,omitempty"`
	RedirectURI  string `json:"redirect_uri"`
}

// ClientStore persists DCR registrations (no TTL: re-registering is cheap but
// churns the upstream's client table).
type ClientStore interface {
	SaveClient(ctx context.Context, key string, c RegisteredClient) error
	GetClient(ctx context.Context, key string) (*RegisteredClient, error)
}

// UpstreamRegistrar discovers upstream authorization servers and maintains
// the gateway's dynamically registered clients.
type UpstreamRegistrar struct {
	clients ClientStore
	http    *http.Client

	mu        sync.Mutex
	discovery map[string]discoveryEntry // upstream URL -> cached metadata
}

type discoveryEntry struct {
	meta    *UpstreamAuthServer
	expires time.Time
}

const discoveryTTL = time.Hour

func NewUpstreamRegistrar(clients ClientStore, client *http.Client) *UpstreamRegistrar {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &UpstreamRegistrar{
		clients:   clients,
		http:      client,
		discovery: map[string]discoveryEntry{},
	}
}

// Discover resolves the upstream MCP URL to its authorization-server
// metadata: protected-resource metadata first (path-inserted, then root),
// then the AS document (OAuth metadata, then OIDC discovery).
func (r *UpstreamRegistrar) Discover(ctx context.Context, upstreamURL string) (*UpstreamAuthServer, error) {
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

func (r *UpstreamRegistrar) discover(ctx context.Context, upstreamURL string) (*UpstreamAuthServer, error) {
	u, err := url.Parse(upstreamURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("oauth dcr: bad upstream url %q", upstreamURL)
	}
	origin := u.Scheme + "://" + u.Host

	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
		ScopesSupported      []string `json:"scopes_supported"`
	}
	// RFC 9728: path-inserted well-known first, then root.
	candidates := []string{}
	if p := strings.TrimSuffix(u.Path, "/"); p != "" && p != "/" {
		candidates = append(candidates, origin+"/.well-known/oauth-protected-resource"+p)
	}
	candidates = append(candidates, origin+"/.well-known/oauth-protected-resource")
	found := false
	for _, c := range candidates {
		if err := r.getJSON(ctx, c, &prm); err == nil && len(prm.AuthorizationServers) > 0 {
			found = true
			break
		}
	}
	if !found {
		return nil, fmt.Errorf("%w (%s)", ErrUpstreamNotDiscoverable, upstreamURL)
	}

	as := strings.TrimSuffix(prm.AuthorizationServers[0], "/")
	var doc UpstreamAuthServer
	asu, err := url.Parse(as)
	if err != nil || asu.Host == "" {
		return nil, fmt.Errorf("oauth dcr: bad authorization server %q", as)
	}
	asOrigin := asu.Scheme + "://" + asu.Host
	asPath := strings.TrimSuffix(asu.Path, "/")
	// RFC 8414 path-aware lookups, then OIDC discovery.
	asCandidates := []string{
		asOrigin + "/.well-known/oauth-authorization-server" + asPath,
		asOrigin + "/.well-known/openid-configuration" + asPath,
		as + "/.well-known/openid-configuration",
	}
	ok := false
	for _, c := range asCandidates {
		if err := r.getJSON(ctx, c, &doc); err == nil && doc.AuthorizationEndpoint != "" && doc.TokenEndpoint != "" {
			ok = true
			break
		}
	}
	if !ok {
		return nil, fmt.Errorf("oauth dcr: no authorization-server metadata at %s", as)
	}
	if len(doc.ScopesSupported) == 0 {
		doc.ScopesSupported = prm.ScopesSupported
	}
	doc.Resource = prm.Resource
	if doc.Resource == "" {
		doc.Resource = upstreamURL
	}
	return &doc, nil
}

// EnsureClient returns the gateway's registered client at the upstream,
// registering via RFC 7591 on first use. Key scopes the registration per
// (gateway, registry) so tenants never share a client identity.
func (r *UpstreamRegistrar) EnsureClient(ctx context.Context, key string, meta *UpstreamAuthServer, redirectURI string) (*RegisteredClient, error) {
	if c, err := r.clients.GetClient(ctx, key); err == nil && c != nil && c.RedirectURI == redirectURI {
		return c, nil
	}
	if meta.RegistrationEndpoint == "" {
		return nil, fmt.Errorf("%w: authorization server has no registration_endpoint", ErrUpstreamNotDiscoverable)
	}
	// Public client + PKCE, mirroring how MCP clients register (RFC 7591).
	body, _ := json.Marshal(map[string]any{
		"client_name":                "TrustGate MCP Gateway",
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
		return nil, fmt.Errorf("oauth dcr: registration rejected (status %d): %s", res.StatusCode, truncate(raw, 200))
	}
	var doc struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.ClientID == "" {
		return nil, fmt.Errorf("oauth dcr: registration response has no client_id")
	}
	client := &RegisteredClient{ClientID: doc.ClientID, ClientSecret: doc.ClientSecret, RedirectURI: redirectURI}
	if err := r.clients.SaveClient(ctx, key, *client); err != nil {
		return nil, err
	}
	return client, nil
}

// CachedClient returns the stored registration without registering (used by
// the refresh path, which must not mint new registrations).
func (r *UpstreamRegistrar) CachedClient(ctx context.Context, key string) (*RegisteredClient, error) {
	return r.clients.GetClient(ctx, key)
}

func (r *UpstreamRegistrar) getJSON(ctx context.Context, rawurl string, out any) error {
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

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
