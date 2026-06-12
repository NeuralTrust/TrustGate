package oauth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
)

var (
	ErrNoAuthorizationServer = errors.New("oauth: no authorization server configured")
	ErrAmbiguousAuthorizationServer = errors.New("oauth: multiple authorization servers configured")
	ErrRegistrationUnavailable = errors.New("oauth: dynamic client registration unavailable")
)

const asMetadataTTL = time.Hour

type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
}

type RegisterRequest struct {
	RedirectURIs []string `json:"redirect_uris"`
	ClientName   string   `json:"client_name,omitempty"`
}

type RegisterResponse struct {
	ClientID                string   `json:"client_id"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
}

type MetadataService interface {
	ProtectedResource(ctx context.Context, baseURL, resource string) (*ProtectedResourceMetadata, error)
	AuthorizationServer(ctx context.Context, baseURL string) (map[string]any, error)
	RegisterClient(ctx context.Context, req RegisterRequest) (*RegisterResponse, error)
}

var _ MetadataService = (*metadataService)(nil)

type metadataService struct {
	credentials appauth.CredentialFinder
	paths       appconsumer.PathResolver
	client      *http.Client

	mu      sync.Mutex
	asCache map[string]asCacheEntry
}

type asCacheEntry struct {
	doc       map[string]any
	fetchedAt time.Time
}

func NewMetadataService(credentials appauth.CredentialFinder, paths appconsumer.PathResolver, client *http.Client) MetadataService {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &metadataService{credentials: credentials, paths: paths, client: client, asCache: map[string]asCacheEntry{}}
}

func (s *metadataService) ProtectedResource(ctx context.Context, baseURL, resource string) (*ProtectedResourceMetadata, error) {
	auths, err := s.resourceAuths(ctx, resource)
	if err != nil {
		return nil, err
	}
	meta := &ProtectedResourceMetadata{
		Resource:               resource,
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        scopesOf(auths),
	}
	if len(issuersOf(auths)) > 0 {
		meta.AuthorizationServers = []string{baseURL}
	}
	return meta, nil
}

func (s *metadataService) resourceAuths(ctx context.Context, resource string) ([]*authdomain.Auth, error) {
	if s.paths != nil && resource != "" {
		if u, err := url.Parse(resource); err == nil && u.Path != "" {
			matches, err := s.paths.Match(ctx, u.Host, u.Path)
			if err == nil && len(matches) > 0 {
				var out []*authdomain.Auth
				for _, m := range matches {
					for _, a := range m.Auths {
						if a.Enabled && a.Type == authdomain.TypeOAuth2 && a.Config.OAuth2 != nil {
							out = append(out, a)
						}
					}
				}
				if len(out) > 0 {
					return out, nil
				}
			}
		}
	}
	auths, err := s.credentials.OAuth2Auths(ctx)
	if err != nil {
		return nil, fmt.Errorf("oauth: load oauth2 auths: %w", err)
	}
	return auths, nil
}

func (s *metadataService) AuthorizationServer(ctx context.Context, baseURL string) (map[string]any, error) {
	auths, err := s.credentials.OAuth2Auths(ctx)
	if err != nil {
		return nil, fmt.Errorf("oauth: load oauth2 auths: %w", err)
	}
	if len(issuersOf(auths)) == 0 {
		return nil, ErrNoAuthorizationServer
	}
	doc := map[string]any{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/oauth/authorize",
		"token_endpoint":                        baseURL + "/oauth/token",
		"registration_endpoint":                 baseURL + "/oauth/register",
		"response_types_supported":              []string{"code"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":      []string{"S256"},
		"token_endpoint_auth_methods_supported": []string{"none"},
	}
	if scopes := scopesOf(auths); len(scopes) > 0 {
		doc["scopes_supported"] = scopes
	}
	return doc, nil
}

func (s *metadataService) RegisterClient(ctx context.Context, req RegisterRequest) (*RegisterResponse, error) {
	auths, err := s.credentials.OAuth2Auths(ctx)
	if err != nil {
		return nil, fmt.Errorf("oauth: load oauth2 auths: %w", err)
	}
	for _, a := range auths {
		cfg := a.Config.OAuth2
		if cfg == nil || cfg.ClientID == "" {
			continue
		}
		return &RegisterResponse{
			ClientID:                cfg.ClientID,
			RedirectURIs:            req.RedirectURIs,
			ClientName:              req.ClientName,
			GrantTypes:              []string{"authorization_code", "refresh_token"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "none",
		}, nil
	}
	return nil, ErrRegistrationUnavailable
}

func (s *metadataService) fetchASMetadata(ctx context.Context, issuer string) (map[string]any, error) {
	s.mu.Lock()
	if e, ok := s.asCache[issuer]; ok && time.Since(e.fetchedAt) < asMetadataTTL {
		s.mu.Unlock()
		return e.doc, nil
	}
	s.mu.Unlock()

	base := strings.TrimSuffix(issuer, "/")
	var lastErr error
	for _, wellKnown := range []string{
		base + "/.well-known/oauth-authorization-server",
		base + "/.well-known/openid-configuration",
	} {
		doc, err := s.fetchJSON(ctx, wellKnown)
		if err != nil {
			lastErr = err
			continue
		}
		s.mu.Lock()
		s.asCache[issuer] = asCacheEntry{doc: doc, fetchedAt: time.Now()}
		s.mu.Unlock()
		return doc, nil
	}
	return nil, fmt.Errorf("oauth: fetch AS metadata for %s: %w", issuer, lastErr)
}

func (s *metadataService) fetchJSON(ctx context.Context, url string) (map[string]any, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d from %s", res.StatusCode, url)
	}
	var doc map[string]any
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, err
	}
	return doc, nil
}

func issuersOf(auths []*authdomain.Auth) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, a := range auths {
		cfg := a.Config.OAuth2
		if cfg == nil || cfg.Issuer == "" {
			continue
		}
		if _, ok := seen[cfg.Issuer]; ok {
			continue
		}
		seen[cfg.Issuer] = struct{}{}
		out = append(out, cfg.Issuer)
	}
	return out
}

func scopesOf(auths []*authdomain.Auth) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, a := range auths {
		cfg := a.Config.OAuth2
		if cfg == nil {
			continue
		}
		for _, s := range cfg.RequiredScopes {
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}
