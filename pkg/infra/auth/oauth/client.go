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
)

type TokenClient interface {
	GetToken(ctx context.Context, dto TokenRequestDTO) (accessToken string, expiresAt time.Time, err error)
}

type tokenClient struct {
	http *http.Client
}

func NewTokenClient(httpClient *http.Client) TokenClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	return &tokenClient{http: httpClient}
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
	ClientSecret string
	UseBasicAuth bool

	Scopes   []string
	Audience string

	Code         string
	RedirectURI  string
	CodeVerifier string

	RefreshToken string

	Username string
	Password string

	Extra map[string]string
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func (c *tokenClient) GetToken(ctx context.Context, dto TokenRequestDTO) (string, time.Time, error) {
	if strings.TrimSpace(dto.TokenURL) == "" {
		return "", time.Time{}, fmt.Errorf("token url is required")
	}
	tokenURL := strings.TrimSpace(strings.TrimPrefix(dto.TokenURL, "@"))
	if dto.GrantType == "" {
		return "", time.Time{}, fmt.Errorf("grant_type is required")
	}

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

	resp, err := c.http.Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()

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

	expiresAt := time.Now().Add(time.Duration(tr.ExpiresIn) * time.Second)
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
