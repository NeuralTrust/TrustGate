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
	"time"
	"unicode/utf8"

	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
)

const (
	scanPath = "/v1/scan/indirect-prompt-injection"
	// maxTexts and maxTextBytes are what one scan call accepts.
	maxTexts         = 64
	maxTextBytes     = 16 << 10
	maxResponseBytes = 1 << 20
	defaultTimeout   = 30 * time.Second
)

type scanner struct {
	client       *http.Client
	url          string
	clientID     string
	clientSecret string
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
	return &scanner{client: &http.Client{Timeout: timeout}, url: baseURL + scanPath, clientID: clientID, clientSecret: clientSecret}
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

func (s *scanner) ScanIndirectPromptInjection(ctx context.Context, texts []string) ([]appregistry.SkillScan, error) {
	out := make([]appregistry.SkillScan, 0, len(texts))
	for start := 0; start < len(texts); start += maxTexts {
		batch := texts[start:min(start+maxTexts, len(texts))]
		scans, err := s.scan(ctx, batch)
		if err != nil {
			return nil, err
		}
		out = append(out, scans...)
	}
	return out, nil
}

func (s *scanner) scan(ctx context.Context, texts []string) ([]appregistry.SkillScan, error) {
	body := scanRequest{Texts: make([]string, len(texts))}
	for i, text := range texts {
		body.Texts[i] = truncate(text, maxTextBytes)
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.SetBasicAuth(s.clientID, s.clientSecret)
	res, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("trustguard scan: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("trustguard scan: status %d", res.StatusCode)
	}
	var answer scanResponse
	if err := json.NewDecoder(io.LimitReader(res.Body, maxResponseBytes)).Decode(&answer); err != nil {
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
