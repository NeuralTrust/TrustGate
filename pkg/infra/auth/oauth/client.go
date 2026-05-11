package oauth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"golang.org/x/sync/singleflight"
)

type TokenClient interface {
	GetToken(ctx context.Context, dto TokenRequestDTO) (accessToken string, expiresAt time.Time, err error)
}

const (
	oauthRedisTokenPrefix = "oauth:token:"
	// oauthTokenReuseSkew drops entries slightly before upstream expiry so we do not reuse almost-expired tokens.
	oauthTokenReuseSkew = 45 * time.Second
)

type tokenClient struct {
	http        *http.Client
	client      cache.Client
	tokenFlight singleflight.Group
}

func NewTokenClient(client cache.Client, opts ...TokenClientOption) TokenClient {
	tc := &tokenClient{
		http:   &http.Client{Timeout: 30 * time.Second},
		client: client,
	}
	for _, opt := range opts {
		opt(tc)
	}
	return tc
}

type GrantType string

const (
	GrantTypeClientCredentials GrantType = "client_credentials"
	GrantTypeAuthorizationCode GrantType = "authorization_code"
	GrantTypePassword          GrantType = "password"
)

type TokenRequestDTO struct {
	TokenURL string

	GrantType GrantType

	ClientID     string
	ClientSecret string // #nosec G117 -- OAuth DTO field for client credentials flow
	UseBasicAuth bool

	Scopes   []string
	Audience string

	Code         string
	RedirectURI  string
	CodeVerifier string

	RefreshToken string // #nosec G117 -- OAuth DTO field for token refresh flow

	Username string
	Password string // #nosec G117 -- OAuth DTO field for password grant flow

	Extra map[string]string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"` // #nosec G117 -- OAuth token response DTO field
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

type cachedOAuthToken struct {
	AccessToken string    `json:"access_token"` // #nosec G117 -- cached bearer token
	ExpiresAt   time.Time `json:"expires_at"`
}

type tokenFlightResult struct {
	token     string
	expiresAt time.Time
}

func (c *tokenClient) GetToken(ctx context.Context, dto TokenRequestDTO) (string, time.Time, error) {
	if strings.TrimSpace(dto.TokenURL) == "" {
		return "", time.Time{}, fmt.Errorf("token url is required")
	}
	if dto.GrantType == "" {
		return "", time.Time{}, fmt.Errorf("grant_type is required")
	}

	fp := oauthTokenCacheKeyFingerprint(dto)
	cacheable := c.oauthCacheEnabled(dto) && fp != ""

	if cacheable {
		key := oauthRedisTokenPrefix + fp
		if raw, err := c.client.Get(ctx, key); err == nil && raw != "" {
			var entry cachedOAuthToken
			if jsonErr := json.Unmarshal([]byte(raw), &entry); jsonErr == nil && isOAuthCachedTokenUsable(entry) {
				return entry.AccessToken, entry.ExpiresAt, nil
			}
			_ = c.client.Delete(ctx, key)
		}
	}

	if !cacheable {
		return c.exchangeOAuthToken(ctx, dto)
	}

	key := oauthRedisTokenPrefix + fp

	fr, err, _ := c.tokenFlight.Do(key, func() (any, error) {
		if raw, getErr := c.client.Get(ctx, key); getErr == nil && raw != "" {
			var warm cachedOAuthToken
			if jsonErr := json.Unmarshal([]byte(raw), &warm); jsonErr == nil && isOAuthCachedTokenUsable(warm) {
				return tokenFlightResult{token: warm.AccessToken, expiresAt: warm.ExpiresAt}, nil
			}
		}

		token, expiresAt, exErr := c.exchangeOAuthToken(ctx, dto)
		if exErr != nil {
			return nil, exErr
		}
		res := tokenFlightResult{token: token, expiresAt: expiresAt}

		// Persist exactly once inside the flight; waiters must not rewrite Redis (would spam Set).
		persistTTL := oauthCacheTTLFromExpiry(res.expiresAt)
		if persistTTL > 0 {
			entry := cachedOAuthToken{AccessToken: res.token, ExpiresAt: res.expiresAt}
			if payload, marshalErr := json.Marshal(entry); marshalErr == nil {
				_ = c.client.Set(ctx, key, string(payload), persistTTL)
			}
		}

		return res, nil
	})
	if err != nil {
		return "", time.Time{}, err
	}
	res := fr.(tokenFlightResult)
	return res.token, res.expiresAt, nil
}

func (c *tokenClient) oauthCacheEnabled(dto TokenRequestDTO) bool {
	return c.client != nil && shouldCacheOAuthClientCredentialsGrant(dto)
}

func shouldCacheOAuthClientCredentialsGrant(dto TokenRequestDTO) bool {
	return dto.GrantType == GrantTypeClientCredentials
}

func isOAuthCachedTokenUsable(entry cachedOAuthToken) bool {
	if entry.AccessToken == "" || entry.ExpiresAt.IsZero() {
		return false
	}
	return time.Until(entry.ExpiresAt) > oauthTokenReuseSkew
}

// oauthCacheTTLFromExpiry limits Redis retention to cache.UpstreamOauthCacheTTL even when the IdP
// returns a long expires_in so keys align with the upstream OAuth cache policy.
func oauthCacheTTLFromExpiry(expiresAt time.Time) time.Duration {
	window := time.Until(expiresAt) - oauthTokenReuseSkew
	if window <= 0 {
		return 0
	}
	if window > cache.UpstreamOauthCacheTTL {
		return cache.UpstreamOauthCacheTTL
	}
	return window
}

func (c *tokenClient) exchangeOAuthToken(ctx context.Context, dto TokenRequestDTO) (string, time.Time, error) {
	tokenURL := normalizeTokenURLForCache(dto.TokenURL)

	form, err := buildForm(dto)
	if err != nil {
		return "", time.Time{}, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	if dto.UseBasicAuth && dto.ClientID != "" {
		cred := dto.ClientID + ":" + dto.ClientSecret
		req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(cred)))
	}

	resp, err := c.http.Do(req) // #nosec G704 -- tokenURL is from admin-configured upstream settings, not user-controlled
	if err != nil {
		return "", time.Time{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	body, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return "", time.Time{}, fmt.Errorf("failed to read token response body: %w", readErr)
	}
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= 300 {
		trunc := string(body)
		if len(trunc) > 2048 {
			trunc = trunc[:2048] + "...(truncated)"
		}
		return "", time.Time{}, fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, trunc)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return "", time.Time{}, fmt.Errorf("failed to decode token response: %w", err)
	}
	if tr.AccessToken == "" {
		return "", time.Time{}, fmt.Errorf("empty access_token in response")
	}

	// Tokens without expiry are still returned but oauthCacheTTLFromExpiry rejects caching (skew).
	expiresAt := time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
	if tr.ExpiresIn <= 0 {
		expiresAt = time.Time{}
	}

	return tr.AccessToken, expiresAt, nil
}

func buildForm(dto TokenRequestDTO) (url.Values, error) {
	v := url.Values{}
	v.Set("grant_type", string(dto.GrantType))

	if len(dto.Scopes) > 0 {
		v.Set("scope", strings.Join(dto.Scopes, " "))
	}
	if strings.TrimSpace(dto.Audience) != "" {
		v.Set("audience", dto.Audience)
	}

	if !dto.UseBasicAuth && dto.ClientID != "" {
		v.Set("client_id", dto.ClientID)
		if dto.ClientSecret != "" {
			v.Set("client_secret", dto.ClientSecret)
		}
	}

	switch dto.GrantType {
	case GrantTypeClientCredentials:
	case GrantTypeAuthorizationCode:
		if strings.TrimSpace(dto.Code) == "" {
			return nil, fmt.Errorf("authorization_code flow requires code")
		}
		if strings.TrimSpace(dto.RedirectURI) == "" {
			return nil, fmt.Errorf("authorization_code flow requires redirect_uri")
		}
		v.Set("code", dto.Code)
		v.Set("redirect_uri", dto.RedirectURI)

		if strings.TrimSpace(dto.CodeVerifier) != "" {
			v.Set("code_verifier", dto.CodeVerifier)
		}

	case GrantTypePassword:
		if strings.TrimSpace(dto.Username) == "" || strings.TrimSpace(dto.Password) == "" {
			return nil, fmt.Errorf("password flow requires username and password")
		}
		v.Set("username", dto.Username)
		v.Set("password", dto.Password)

	default:
		return nil, fmt.Errorf("unsupported grant_type: %s", dto.GrantType)
	}

	for k, val := range dto.Extra {
		if strings.TrimSpace(k) != "" && val != "" {
			v.Set(k, val)
		}
	}

	return v, nil
}
