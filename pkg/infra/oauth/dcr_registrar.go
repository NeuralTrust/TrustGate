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
func WithClientName(name string) RegistrarOption {
	return func(r *upstreamRegistrar) {
		if trimmed := strings.TrimSpace(name); trimmed != "" {
			r.clientName = trimmed
		}
	}
}

type discoveryEntry struct {
	meta    *appoauth.UpstreamAuthServer
	expires time.Time
}

const discoveryTTL = time.Hour

func NewUpstreamRegistrar(clients appoauth.ClientStore, client *http.Client, opts ...RegistrarOption) appoauth.UpstreamRegistrar {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
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
	cached, cacheErr := r.clients.GetClient(ctx, key)
	if cacheErr == nil && cached != nil && cached.RedirectURI == redirectURI && r.clientNameMatches(cached) {
		return cached, nil
	}
	// A client is already registered but for a different redirect URI or under a
	// different name. Replacing it is deliberate, and it invalidates every
	// refresh token the old client holds, so say so rather than losing those
	// grants silently.
	replacing := cacheErr == nil && cached != nil
	if replacing {
		slog.Warn("oauth dcr: re-registering upstream client because its redirect URI or client name changed; grants held by the previous client can no longer be refreshed",
			"key", key,
			"old_redirect_uri", cached.RedirectURI, "new_redirect_uri", redirectURI,
			"old_client_name", cached.ClientName, "new_client_name", r.clientName)
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
		return nil, fmt.Errorf("oauth dcr: registration rejected (status %d): %s", res.StatusCode, truncate(raw, 200))
	}
	var doc struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil || doc.ClientID == "" {
		return nil, fmt.Errorf("oauth dcr: registration response has no client_id")
	}
	client := &appoauth.RegisteredClient{
		ClientID:     doc.ClientID,
		ClientSecret: doc.ClientSecret,
		RedirectURI:  redirectURI,
		ClientName:   r.clientName,
	}
	if replacing {
		if err := r.clients.SaveClient(ctx, key, *client); err != nil {
			return nil, err
		}
		return client, nil
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
