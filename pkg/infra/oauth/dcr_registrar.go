package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
)

var _ appoauth.UpstreamRegistrar = (*upstreamRegistrar)(nil)

type upstreamRegistrar struct {
	clients appoauth.ClientStore
	http    *http.Client

	mu        sync.Mutex
	discovery map[string]discoveryEntry
}

type discoveryEntry struct {
	meta    *appoauth.UpstreamAuthServer
	expires time.Time
}

const discoveryTTL = time.Hour

func NewUpstreamRegistrar(clients appoauth.ClientStore, client *http.Client) appoauth.UpstreamRegistrar {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &upstreamRegistrar{
		clients:   clients,
		http:      client,
		discovery: map[string]discoveryEntry{},
	}
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

	as := strings.TrimSuffix(prm.AuthorizationServers[0], "/")
	var doc appoauth.UpstreamAuthServer
	asu, err := url.Parse(as)
	if err != nil || asu.Host == "" {
		return nil, fmt.Errorf("oauth dcr: bad authorization server %q", as)
	}
	asOrigin := asu.Scheme + "://" + asu.Host
	asPath := strings.TrimSuffix(asu.Path, "/")
	asCandidates := []string{
		asOrigin + "/.well-known/oauth-authorization-server" + asPath,
		asOrigin + "/.well-known/openid-configuration" + asPath,
		as + "/.well-known/openid-configuration",
	}
	ok := false
	for _, c := range asCandidates {
		var attempt appoauth.UpstreamAuthServer
		if err := r.getJSON(ctx, c, &attempt); err == nil && attempt.AuthorizationEndpoint != "" && attempt.TokenEndpoint != "" {
			doc = attempt
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

func (r *upstreamRegistrar) EnsureClient(ctx context.Context, key string, meta *appoauth.UpstreamAuthServer, redirectURI string) (*appoauth.RegisteredClient, error) {
	if c, err := r.clients.GetClient(ctx, key); err == nil && c != nil && c.RedirectURI == redirectURI {
		return c, nil
	}
	if meta.RegistrationEndpoint == "" {
		return nil, fmt.Errorf("%w: authorization server has no registration_endpoint", appoauth.ErrUpstreamNotDiscoverable)
	}
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
	client := &appoauth.RegisteredClient{ClientID: doc.ClientID, ClientSecret: doc.ClientSecret, RedirectURI: redirectURI}
	if err := r.clients.SaveClient(ctx, key, *client); err != nil {
		return nil, err
	}
	return client, nil
}

func (r *upstreamRegistrar) CachedClient(ctx context.Context, key string) (*appoauth.RegisteredClient, error) {
	return r.clients.GetClient(ctx, key)
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

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "..."
}
