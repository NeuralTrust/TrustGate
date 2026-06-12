package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	appoauth "github.com/NeuralTrust/AgentGateway/pkg/app/oauth"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

var _ appoauth.ProviderClient = (*providerClient)(nil)

type providerClient struct {
	client *http.Client
}

func NewProviderClient(client *http.Client) appoauth.ProviderClient {
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &providerClient{client: client}
}

func (p *providerClient) AuthorizeURL(cfg *registrydomain.MCPAuth, redirectURI, state, challenge string) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", redirectURI)
	q.Set("state", state)
	if len(cfg.Scopes) > 0 {
		q.Set("scope", strings.Join(cfg.Scopes, " "))
	}
	if challenge != "" {
		q.Set("code_challenge", challenge)
		q.Set("code_challenge_method", "S256")
	}
	if cfg.Resource != "" {
		q.Set("resource", cfg.Resource)
	}
	sep := "?"
	if strings.Contains(cfg.AuthorizeURL, "?") {
		sep = "&"
	}
	return cfg.AuthorizeURL + sep + q.Encode()
}

func (p *providerClient) ExchangeCode(ctx context.Context, cfg *registrydomain.MCPAuth, code, redirectURI, verifier string) (*appoauth.ProviderToken, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	if verifier != "" {
		form.Set("code_verifier", verifier)
	}
	if cfg.Resource != "" {
		form.Set("resource", cfg.Resource)
	}
	return p.tokenCall(ctx, cfg.TokenURL, form)
}

func (p *providerClient) Refresh(ctx context.Context, cfg *registrydomain.MCPAuth, refreshToken string) (*appoauth.ProviderToken, error) {
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", refreshToken)
	form.Set("client_id", cfg.ClientID)
	if cfg.ClientSecret != "" {
		form.Set("client_secret", cfg.ClientSecret)
	}
	if cfg.Resource != "" {
		form.Set("resource", cfg.Resource)
	}
	return p.tokenCall(ctx, cfg.TokenURL, form)
}

func (p *providerClient) tokenCall(ctx context.Context, endpoint string, form url.Values) (*appoauth.ProviderToken, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := p.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oauth provider: token call: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("oauth provider: read response: %w", err)
	}
	var doc struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
		Scope        string `json:"scope"`
		Error        string `json:"error"`
		ErrorDesc    string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("oauth provider: non-JSON token response (status %d)", res.StatusCode)
	}
	if res.StatusCode != http.StatusOK || doc.Error != "" || doc.AccessToken == "" {
		return nil, fmt.Errorf("oauth provider: token exchange failed (%s): %s", doc.Error, doc.ErrorDesc)
	}
	out := &appoauth.ProviderToken{AccessToken: doc.AccessToken, RefreshToken: doc.RefreshToken}
	if doc.ExpiresIn > 0 {
		out.ExpiresAt = time.Now().Add(time.Duration(doc.ExpiresIn) * time.Second)
	}
	if doc.Scope != "" {
		out.Scopes = strings.FieldsFunc(doc.Scope, func(r rune) bool { return r == ' ' || r == ',' })
	}
	return out, nil
}
