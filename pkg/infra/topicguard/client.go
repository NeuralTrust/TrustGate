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

// Package topicguard is a client for the Firewall topic-guard API, which
// scores a text against a catalog of customer-defined topics.
package topicguard

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/topicclassifier"
	"github.com/NeuralTrust/TrustGate/pkg/domain/topic"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
)

const (
	classifyPath     = "/v1/topic-guard"
	configPath       = "/v1/topic-guard/config"
	headerToken      = "token"
	contentTypeJSON  = "application/json"
	maxResponseBytes = 4 << 20
	defaultTimeout   = 15 * time.Second

	defaultRetryAfter    = time.Second
	modelVersionTTL      = 5 * time.Minute
	modelVersionRetry    = 30 * time.Second
	peerService          = "firewall-gateway"
	classifySpanName     = "firewall.topic_guard"
	versionSeparator     = "@"
	calibrationSeparator = "+"
)

// TokenProvider supplies authentication tokens for Firewall requests.
type TokenProvider interface {
	Configured() bool
	Invalidate()
	Token() (string, error)
}

var _ topicclassifier.Classifier = (*Client)(nil)

// Client calls the Firewall topic-guard API.
type Client struct {
	http          *http.Client
	baseURL       string
	tokenProvider TokenProvider
	now           func() time.Time

	mu             sync.Mutex
	version        string
	versionErr     error
	versionExpires time.Time
}

// NewClient builds a Client. Missing endpoint credentials leave it
// unconfigured, and every call then returns topic.ErrClassifierNotConfigured.
func NewClient(baseURL string, tokenProvider TokenProvider, timeout time.Duration) *Client {
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	return &Client{
		http: &http.Client{
			Timeout:   timeout,
			Transport: o11y.InternalTransport(peerService, classifySpanName),
		},
		baseURL:       strings.TrimRight(baseURL, "/"),
		tokenProvider: tokenProvider,
		now:           time.Now,
	}
}

// Configured reports whether the endpoint and token provider are configured.
func (c *Client) Configured() bool {
	return c.baseURL != "" && c.tokenProvider != nil && c.tokenProvider.Configured()
}

// Classify scores texts against topics in a single call. Results are
// index-aligned with texts and carry the model version that produced them.
func (c *Client) Classify(ctx context.Context, topics []topic.Topic, threshold *float64, texts []string) ([]topic.Classification, error) {
	if !c.Configured() {
		return nil, topic.ErrClassifierNotConfigured
	}
	if len(texts) == 0 {
		return nil, nil
	}
	if len(texts) > topic.MaxBatchTexts {
		return nil, fmt.Errorf("topicguard: %d texts exceed the batch limit of %d", len(texts), topic.MaxBatchTexts)
	}
	defs := make([]topicDefinition, len(topics))
	for i, t := range topics {
		defs[i] = topicDefinition{Name: t.Name, Definition: t.Definition}
	}
	payload, err := json.Marshal(classifyRequest{Input: texts, Topics: defs, Threshold: threshold})
	if err != nil {
		return nil, fmt.Errorf("topicguard: marshal request: %w", err)
	}
	raw, err := c.do(ctx, http.MethodPost, classifyPath, payload)
	if err != nil {
		return nil, err
	}
	var out []classifyResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("topicguard: decode response: %w", err)
	}
	if len(out) != len(texts) {
		return nil, fmt.Errorf("topicguard: got %d results for %d texts", len(out), len(texts))
	}
	// A failed version lookup still returns the last known version, and the
	// scores are valid either way; the error only matters to cache keying.
	version, _ := c.ModelVersion(ctx)
	results := make([]topic.Classification, len(out))
	for i, r := range out {
		results[i] = toClassification(r, version)
	}
	return results, nil
}

// ModelVersion returns the model and calibration revision currently serving.
// It is cached for a few minutes so a redeploy is picked up without asking on
// every call. On failure it returns the last known version with the error,
// and asks again sooner.
func (c *Client) ModelVersion(ctx context.Context) (string, error) {
	if !c.Configured() {
		return "", topic.ErrClassifierNotConfigured
	}
	c.mu.Lock()
	if c.now().Before(c.versionExpires) {
		version, err := c.version, c.versionErr
		c.mu.Unlock()
		return version, err
	}
	c.mu.Unlock()

	version, err := c.fetchModelVersion(ctx)

	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.versionErr = err
		c.versionExpires = c.now().Add(modelVersionRetry)
		return c.version, err
	}
	c.version, c.versionErr = version, nil
	c.versionExpires = c.now().Add(modelVersionTTL)
	return version, nil
}

func (c *Client) fetchModelVersion(ctx context.Context) (string, error) {
	raw, err := c.do(ctx, http.MethodGet, configPath, nil)
	if err != nil {
		return "", err
	}
	var cfg configResponse
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return "", fmt.Errorf("topicguard: decode config: %w", err)
	}
	version := cfg.Name
	if cfg.Revision != nil && *cfg.Revision != "" {
		version += versionSeparator + *cfg.Revision
	}
	if cfg.CandidateRevision != nil && *cfg.CandidateRevision != "" {
		version += calibrationSeparator + *cfg.CandidateRevision
	}
	return version, nil
}

func (c *Client) do(ctx context.Context, method, path string, payload []byte) ([]byte, error) {
	token, err := c.tokenProvider.Token()
	if err != nil {
		return nil, fmt.Errorf("topicguard: get token: %w", err)
	}
	var body io.Reader
	if payload != nil {
		body = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, fmt.Errorf("topicguard: build request: %w", err)
	}
	req.Header.Set(headerToken, token)
	if payload != nil {
		req.Header.Set("Content-Type", contentTypeJSON)
	}

	res, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("topicguard: %s %s: %w", method, path, err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
	}()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("topicguard: read response: %w", err)
	}
	switch {
	case res.StatusCode == http.StatusUnauthorized:
		c.tokenProvider.Invalidate()
		return nil, topic.ErrClassifierUnauthorized
	case res.StatusCode == http.StatusServiceUnavailable:
		return nil, &topic.BackpressureError{RetryAfter: retryAfter(res.Header.Get("Retry-After"))}
	case res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices:
		return nil, fmt.Errorf("topicguard: unexpected status %d", res.StatusCode)
	}
	return raw, nil
}

func retryAfter(header string) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || seconds <= 0 {
		return defaultRetryAfter
	}
	return time.Duration(seconds) * time.Second
}

func toClassification(r classifyResponse, version string) topic.Classification {
	scores := make([]topic.Score, 0, len(r.TopicScores))
	for name, s := range r.TopicScores {
		scores = append(scores, topic.Score{Topic: name, Probability: s.Probability, Matched: s.Blocked})
	}
	slices.SortFunc(scores, func(a, b topic.Score) int { return cmp.Compare(a.Topic, b.Topic) })
	matched := slices.Clone(r.BlockedTopics)
	slices.Sort(matched)
	return topic.Classification{
		Scores:       scores,
		Matched:      matched,
		Windows:      r.NWindows,
		ModelVersion: version,
	}
}
