package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenClient_DefaultHTTPClient(t *testing.T) {
	client := NewTokenClient()

	assert.NotNil(t, client)
	tc, ok := client.(*tokenClient)
	require.True(t, ok)
	assert.NotNil(t, tc.http)
	assert.Equal(t, 30*time.Second, tc.http.Timeout)
}

func TestNewTokenClient_WithHTTPClient(t *testing.T) {
	customClient := &http.Client{Timeout: 30 * time.Second}

	client := NewTokenClient(WithHTTPClient(customClient))

	tc, ok := client.(*tokenClient)
	require.True(t, ok)
	assert.Equal(t, customClient, tc.http)
	assert.Equal(t, 30*time.Second, tc.http.Timeout)
}

func TestNewTokenClient_WithHTTPClient_Nil(t *testing.T) {
	client := NewTokenClient(WithHTTPClient(nil))

	tc, ok := client.(*tokenClient)
	require.True(t, ok)
	assert.NotNil(t, tc.http)
	assert.Equal(t, 30*time.Second, tc.http.Timeout)
}

func TestNewTokenClient_WithTimeout(t *testing.T) {
	client := NewTokenClient(WithTimeout(5 * time.Second))

	tc, ok := client.(*tokenClient)
	require.True(t, ok)
	assert.Equal(t, 5*time.Second, tc.http.Timeout)
}

func TestGetToken_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "test-token-123",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	client := NewTokenClient()
	token, expiresAt, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL:     server.URL,
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	})

	assert.NoError(t, err)
	assert.Equal(t, "test-token-123", token)
	assert.True(t, expiresAt.After(time.Now()))
}

func TestGetToken_EmptyTokenURL(t *testing.T) {
	client := NewTokenClient()

	_, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		GrantType: GrantTypeClientCredentials,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "token url is required")
}

func TestGetToken_EmptyGrantType(t *testing.T) {
	client := NewTokenClient()

	_, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL: "http://example.com/token",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "grant_type is required")
}

func TestGetToken_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte("invalid credentials"))
	}))
	defer server.Close()

	client := NewTokenClient()
	_, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL:     server.URL,
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "test-client",
		ClientSecret: "wrong-secret",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status 401")
}

func TestGetToken_EmptyAccessToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "",
			"token_type":   "Bearer",
		})
	}))
	defer server.Close()

	client := NewTokenClient()
	_, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  server.URL,
		GrantType: GrantTypeClientCredentials,
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty access_token")
}

func TestGetToken_WithBasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		assert.Contains(t, authHeader, "Basic ")

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "basic-auth-token",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	client := NewTokenClient()
	token, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL:     server.URL,
		GrantType:    GrantTypeClientCredentials,
		ClientID:     "test-client",
		ClientSecret: "test-secret",
		UseBasicAuth: true,
	})

	assert.NoError(t, err)
	assert.Equal(t, "basic-auth-token", token)
}

func TestGetToken_AuthorizationCodeFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
		assert.Equal(t, "auth-code-123", r.FormValue("code"))
		assert.Equal(t, "http://localhost/callback", r.FormValue("redirect_uri"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "auth-code-token",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	client := NewTokenClient()
	token, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL:    server.URL,
		GrantType:   GrantTypeAuthorizationCode,
		Code:        "auth-code-123",
		RedirectURI: "http://localhost/callback",
	})

	assert.NoError(t, err)
	assert.Equal(t, "auth-code-token", token)
}

func TestGetToken_AuthorizationCodeFlow_MissingCode(t *testing.T) {
	client := NewTokenClient()

	_, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL:    "http://example.com/token",
		GrantType:   GrantTypeAuthorizationCode,
		RedirectURI: "http://localhost/callback",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires code")
}

func TestGetToken_PasswordFlow(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := r.ParseForm()
		require.NoError(t, err)

		assert.Equal(t, "password", r.FormValue("grant_type"))
		assert.Equal(t, "testuser", r.FormValue("username"))
		assert.Equal(t, "testpass", r.FormValue("password"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"access_token": "password-token",
			"expires_in":   3600,
		})
	}))
	defer server.Close()

	client := NewTokenClient()
	token, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  server.URL,
		GrantType: GrantTypePassword,
		Username:  "testuser",
		Password:  "testpass",
	})

	assert.NoError(t, err)
	assert.Equal(t, "password-token", token)
}

func TestGetToken_PasswordFlow_MissingCredentials(t *testing.T) {
	client := NewTokenClient()

	_, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  "http://example.com/token",
		GrantType: GrantTypePassword,
		Username:  "testuser",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "requires username and password")
}

func TestGetToken_UnsupportedGrantType(t *testing.T) {
	client := NewTokenClient()

	_, _, err := client.GetToken(context.Background(), TokenRequestDTO{
		TokenURL:  "http://example.com/token",
		GrantType: "unsupported",
	})

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported grant_type")
}
