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

// Package trustguardscan scores registry content with TrustGuard outside any
// policy: the gateway's own check of what it registers.
package trustguardscan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

const (
	scanPath  = "/v1/scan/indirect-prompt-injection"
	tokenPath = "/v1/token"
	// scopeScan is the token scope TrustGuard admits on the scan route only.
	scopeScan = "scan"
	// maxTexts and maxTextBytes are what one scan call accepts.
	maxTexts         = 64
	maxTextBytes     = 16 << 10
	maxResponseBytes = 1 << 20
	defaultTimeout   = 30 * time.Second
	// tokenRefreshSkew renews a token this long before it expires.
	tokenRefreshSkew = 30 * time.Second
)

type cachedToken struct {
	value     string
	expiresAt time.Time
}

type scanner struct {
	client       *http.Client
	baseURL      string
	clientID     string
	clientSecret string

	mu     sync.Mutex
	tokens map[ids.GatewayID]cachedToken
}

// New returns the scanner of the TrustGuard at baseURL, signed in with its
// platform credentials, or nil when any of them is missing.
func New(baseURL, clientID, clientSecret string, timeout time.Duration) appregistry.SkillScanner {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" || clientID == "" || clientSecret == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &scanner{
		client:       &http.Client{Timeout: timeout},
		baseURL:      baseURL,
		clientID:     clientID,
		clientSecret: clientSecret,
		tokens:       map[ids.GatewayID]cachedToken{},
	}
}

type scanRequest struct {
	Texts []string `json:"texts"`
}

type scanResponse struct {
	Results []struct {
		Flagged bool    `json:"flagged"`
		Score   float64 `json:"score"`
	} `json:"results"`
}

func (s *scanner) ScanIndirectPromptInjection(ctx context.Context, gatewayID ids.GatewayID, texts []string) ([]appregistry.SkillScan, error) {
	token, err := s.token(ctx, gatewayID)
	if err != nil {
		return nil, err
	}
	out := make([]appregistry.SkillScan, 0, len(texts))
	for start := 0; start < len(texts); start += maxTexts {
		batch := texts[start:min(start+maxTexts, len(texts))]
		scans, err := s.scan(ctx, token, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, scans...)
	}
	return out, nil
}

func (s *scanner) scan(ctx context.Context, token string, texts []string) ([]appregistry.SkillScan, error) {
	body := scanRequest{Texts: make([]string, len(texts))}
	for i, text := range texts {
		body.Texts[i] = truncate(text, maxTextBytes)
	}
	var answer scanResponse
	if err := s.post(ctx, scanPath, token, body, &answer); err != nil {
		return nil, fmt.Errorf("trustguard scan: %w", err)
	}
	if len(answer.Results) != len(texts) {
		return nil, fmt.Errorf("trustguard scan: %d results for %d texts", len(answer.Results), len(texts))
	}
	out := make([]appregistry.SkillScan, len(answer.Results))
	for i, r := range answer.Results {
		out[i] = appregistry.SkillScan{Flagged: r.Flagged, Score: r.Score}
	}
	return out, nil
}

type tokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
	GatewayID    string `json:"gateway_id"`
}

type tokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// token is a scan token for gatewayID, reused until shortly before it expires.
func (s *scanner) token(ctx context.Context, gatewayID ids.GatewayID) (string, error) {
	s.mu.Lock()
	cached, ok := s.tokens[gatewayID]
	s.mu.Unlock()
	if ok && time.Now().Before(cached.expiresAt) {
		return cached.value, nil
	}
	var answer tokenResponse
	err := s.post(ctx, tokenPath, "", tokenRequest{
		GrantType:    "client_credentials",
		ClientID:     s.clientID,
		ClientSecret: s.clientSecret,
		Scope:        scopeScan,
		GatewayID:    gatewayID.String(),
	}, &answer)
	if err != nil {
		return "", fmt.Errorf("trustguard scan token: %w", err)
	}
	if answer.AccessToken == "" {
		return "", fmt.Errorf("trustguard scan token: no access_token")
	}
	expiresAt := time.Now().Add(time.Duration(answer.ExpiresIn)*time.Second - tokenRefreshSkew)
	s.mu.Lock()
	s.tokens[gatewayID] = cachedToken{value: answer.AccessToken, expiresAt: expiresAt}
	s.mu.Unlock()
	return answer.AccessToken, nil
}

// post sends body as JSON to path, with token as its bearer when set, and
// decodes a 200 answer into out.
func (s *scanner) post(ctx context.Context, path, token string, body, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, maxResponseBytes)).Decode(out)
}

// truncate cuts text to at most n bytes without splitting a rune.
func truncate(text string, n int) string {
	if len(text) <= n {
		return text
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(text[cut]) {
		cut--
	}
	return text[:cut]
}
