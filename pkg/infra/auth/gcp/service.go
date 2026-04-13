package gcp

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/golang-jwt/jwt/v5"
)

var requiredSAFields = []string{
	"project_id",
	"private_key",
	"client_email",
	"token_uri",
}

//go:generate mockery --name=ServiceAccountService --dir=. --output=./mocks --filename=service_account_service_mock.go --case=underscore --with-expecter
type ServiceAccountService interface {
	ValidateSA(base64Encoded string) error
	EncryptSA(base64Encoded string) (string, error)
	DecryptSA(upstreamID, targetID, encrypted string) (map[string]string, error)
	InvalidateSACache(upstreamID, targetID string)
	GetAccessToken(ctx context.Context, upstreamID, targetID string, sa map[string]string) (string, error)
	ResolveSAFromEnv() (string, error)
}

const (
	defaultTokenExpiry  = 3600
	grantTypeJWTBearer  = "urn:ietf:params:oauth:grant-type:jwt-bearer" // #nosec G101 -- OAuth grant type URI, not a credential
	defaultScope        = "https://www.googleapis.com/auth/cloud-platform"
	maxTokenResponseLen = 1 << 20 // 1 MiB
)

type cachedToken struct {
	accessToken string
	expiresAt   time.Time
}

type serviceAccountService struct {
	crypto     crypto.EncryptionService
	cache      sync.Map
	tokenCache sync.Map
	httpClient *http.Client
}

func NewServiceAccountService(cryptoSvc crypto.EncryptionService) ServiceAccountService {
	return &serviceAccountService{
		crypto:     cryptoSvc,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func saCacheKey(upstreamID, targetID string) string {
	return upstreamID + ":" + targetID
}

func tokenCacheKey(upstreamID, targetID string) string {
	return upstreamID + ":" + targetID + ":token"
}

func (s *serviceAccountService) ValidateSA(base64Encoded string) error {
	raw, err := base64.StdEncoding.DecodeString(base64Encoded)
	if err != nil {
		return fmt.Errorf("invalid base64 encoding: %w", err)
	}

	var sa map[string]any
	if err := json.Unmarshal(raw, &sa); err != nil {
		return fmt.Errorf("invalid JSON in service account: %w", err)
	}

	saType, _ := sa["type"].(string)
	if saType != "service_account" {
		return fmt.Errorf("service account type must be 'service_account', got %q", saType)
	}

	for _, field := range requiredSAFields {
		val, _ := sa[field].(string)
		if val == "" {
			return fmt.Errorf("missing required field %q in service account", field)
		}
	}
	return nil
}

func (s *serviceAccountService) ResolveSAFromEnv() (string, error) {
	filePath := os.Getenv("GOOGLE_APPLICATION_CREDENTIALS")
	if filePath == "" {
		return "", fmt.Errorf("GOOGLE_APPLICATION_CREDENTIALS is not set")
	}
	data, err := os.ReadFile(filePath) // #nosec G304 -- path comes from GOOGLE_APPLICATION_CREDENTIALS env var
	if err != nil {
		return "", fmt.Errorf("failed to read service account file %q: %w", filePath, err)
	}
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return "", fmt.Errorf("file %q is not valid JSON: %w", filePath, err)
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (s *serviceAccountService) EncryptSA(base64Encoded string) (string, error) {
	if s.crypto == nil {
		return "", fmt.Errorf("encryption service not configured: set ENCRYPTION_KEY")
	}
	encrypted, err := s.crypto.Encrypt([]byte(base64Encoded))
	if err != nil {
		return "", fmt.Errorf("failed to encrypt service account: %w", err)
	}
	return base64.StdEncoding.EncodeToString(encrypted), nil
}

func (s *serviceAccountService) DecryptSA(upstreamID, targetID, encrypted string) (map[string]string, error) {
	cacheKey := saCacheKey(upstreamID, targetID)
	if cached, ok := s.cache.Load(cacheKey); ok {
		return cached.(map[string]string), nil
	}

	if s.crypto == nil {
		return nil, fmt.Errorf("encryption service not configured: set ENCRYPTION_KEY")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 in encrypted service account: %w", err)
	}

	decrypted, err := s.crypto.Decrypt(ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt service account: %w", err)
	}

	saJSON, err := base64.StdEncoding.DecodeString(string(decrypted))
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64 service account: %w", err)
	}

	var sa map[string]string
	if err := json.Unmarshal(saJSON, &sa); err != nil {
		return nil, fmt.Errorf("failed to parse service account JSON: %w", err)
	}

	s.cache.Store(cacheKey, sa)
	return sa, nil
}

func (s *serviceAccountService) InvalidateSACache(upstreamID, targetID string) {
	s.cache.Delete(saCacheKey(upstreamID, targetID))
	s.tokenCache.Delete(tokenCacheKey(upstreamID, targetID))
}

func (s *serviceAccountService) GetAccessToken(ctx context.Context, upstreamID, targetID string, sa map[string]string) (string, error) {
	tokenKey := tokenCacheKey(upstreamID, targetID)
	if cached, ok := s.tokenCache.Load(tokenKey); ok {
		ct := cached.(*cachedToken)
		if time.Now().Before(ct.expiresAt.Add(-60 * time.Second)) {
			return ct.accessToken, nil
		}
	}

	privateKeyPEM := sa["private_key"]
	if privateKeyPEM == "" {
		return "", fmt.Errorf("missing private_key in service account")
	}

	key, err := parseRSAPrivateKey(privateKeyPEM)
	if err != nil {
		return "", fmt.Errorf("failed to parse private key: %w", err)
	}

	tokenURI := sa["token_uri"]
	if tokenURI == "" {
		tokenURI = "https://oauth2.googleapis.com/token" // #nosec G101 -- default Google token endpoint, not a credential
	}

	clientEmail := sa["client_email"]
	if clientEmail == "" {
		return "", fmt.Errorf("missing client_email in service account")
	}

	now := time.Now()
	claims := jwt.MapClaims{
		"iss":   clientEmail,
		"sub":   clientEmail,
		"aud":   tokenURI,
		"iat":   now.Unix(),
		"exp":   now.Add(time.Duration(defaultTokenExpiry) * time.Second).Unix(),
		"scope": defaultScope,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = sa["private_key_id"]

	signedJWT, err := token.SignedString(key)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	form := url.Values{}
	form.Set("grant_type", grantTypeJWTBearer)
	form.Set("assertion", signedJWT)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURI, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTokenResponseLen))
	if err != nil {
		return "", fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= 300 {
		return "", fmt.Errorf("token endpoint returned status %d: %s", resp.StatusCode, truncate(string(body), 512))
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"` // #nosec G101 -- token response field
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return "", fmt.Errorf("failed to decode token response: %w", err)
	}
	if tokenResp.AccessToken == "" {
		return "", fmt.Errorf("empty access_token in response")
	}

	expiresAt := now.Add(time.Duration(tokenResp.ExpiresIn) * time.Second)
	s.tokenCache.Store(tokenKey, &cachedToken{
		accessToken: tokenResp.AccessToken,
		expiresAt:   expiresAt,
	})

	return tokenResp.AccessToken, nil
}

func parseRSAPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		var rsaKey *rsa.PrivateKey
		rsaKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key as PKCS8 or PKCS1: %w", err)
		}
		return rsaKey, nil
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}
	return rsaKey, nil
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "...(truncated)"
}
