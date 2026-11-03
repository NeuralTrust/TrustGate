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

package trustguard

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/common/requestmeta"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
)

const (
	defaultV3Timeout = 5 * time.Second
	// v3MaxInFlight bounds the Guard calls waiting at once. A Guard that is down
	// or slow would otherwise hold one goroutine and one connection per request
	// for its whole timeout; past the bound a copy is dropped and counted.
	v3MaxInFlight = 256

	v3PeerService      = "guard"
	v3EvaluateSpanName = "guard.evaluate"

	maxLoggedV3ErrorBytes = 512
)

// V3Config is Guard (TrustGuard v3), which receives a copy of every
// evaluation of the gateways it lists.
type V3Config struct {
	BaseURL      string
	Timeout      time.Duration
	ClientID     string
	ClientSecret string
	// Gateways maps each gateway that sends to Guard to the Guard integration
	// its token names. An empty integration id is the policy's collector_id.
	Gateways map[string]string
}

func (c V3Config) enabled() bool {
	return strings.TrimSpace(c.BaseURL) != "" &&
		strings.TrimSpace(c.ClientID) != "" &&
		strings.TrimSpace(c.ClientSecret) != "" &&
		len(c.Gateways) > 0
}

// v3Request is Guard's evaluate body. Guard decodes it strictly and knows no
// v2 name: consumer_id is application_id, and there is no a2a.
type v3Request struct {
	OriginalRequest *requestmeta.OriginalRequest `json:"original_request,omitempty"`
	Payload         json.RawMessage              `json:"payload"`
	Direction       string                       `json:"direction"`
	Protocol        string                       `json:"protocol"`
	GatewayID       string                       `json:"gateway_id"`
	SessionID       string                       `json:"session_id,omitempty"`
	ApplicationID   string                       `json:"application_id,omitempty"`
	Attributes      v3Attributes                 `json:"attributes"`
}

type v3Attributes struct {
	ContentType string         `json:"content_type"`
	Model       GuardModel     `json:"model"`
	User        *GuardUser     `json:"user,omitempty"`
	Application *v3Application `json:"application,omitempty"`
	MCPServer   *v3MCPServer   `json:"mcp_server,omitempty"`
	Stream      *GuardStream   `json:"stream,omitempty"`
}

type v3Application struct {
	Name string `json:"name"`
}

// v3MCPServer carries Guard's canonical id of the server: the catalog code, or
// the registry id of a server added by URL.
type v3MCPServer struct {
	ID string `json:"id"`
}

func toV3Request(body GuardRequest) v3Request {
	req := v3Request{
		OriginalRequest: body.OriginalRequest,
		Payload:         append(json.RawMessage(nil), body.Payload...),
		Direction:       body.Direction,
		Protocol:        body.Protocol,
		GatewayID:       body.GatewayID,
		SessionID:       body.SessionID,
		ApplicationID:   strings.TrimSpace(body.ConsumerID),
		Attributes: v3Attributes{
			ContentType: body.Attributes.ContentType,
			Model:       body.Attributes.Model,
			User:        body.Attributes.User,
			MCPServer:   v3MCPServerOf(body.Attributes.MCPServer),
			Stream:      body.Attributes.Stream,
		},
	}
	if c := body.Attributes.Consumer; c != nil && c.Name != "" {
		req.Attributes.Application = &v3Application{Name: c.Name}
	}
	return req
}

func v3MCPServerOf(server *GuardMCPServer) *v3MCPServer {
	if server == nil {
		return nil
	}
	if server.Code != "" {
		return &v3MCPServer{ID: server.Code}
	}
	return &v3MCPServer{ID: server.ID}
}

type v3StatusError struct {
	status int
	body   string
}

func (e *v3StatusError) Error() string {
	return fmt.Sprintf("guard: evaluate status %d", e.status)
}

// v3Sender sends Guard its copy of an evaluation. Nothing it does reaches the
// request: the call runs detached, under its own timeout, and its outcome is
// only logged and counted.
type v3Sender struct {
	baseURL  string
	timeout  time.Duration
	gateways map[string]string
	http     *http.Client
	tokens   *tokenManager
	logger   *slog.Logger

	slots    chan struct{}
	inFlight sync.WaitGroup
}

func newV3Sender(cfg V3Config, base http.RoundTripper, logger *slog.Logger) *v3Sender {
	if !cfg.enabled() {
		if len(cfg.Gateways) > 0 && logger != nil {
			logger.Warn("guard v3 copies are off: base URL or client credentials missing",
				slog.Int("gateways", len(cfg.Gateways)))
		}
		return nil
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultV3Timeout
	}
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: o11y.InternalTransportOver(base, v3PeerService, v3EvaluateSpanName),
	}
	tokens := newTokenManager(httpClient, cfg.ClientID, cfg.ClientSecret)
	tokens.v3 = true
	gateways := make(map[string]string, len(cfg.Gateways))
	for gw, integration := range cfg.Gateways {
		gateways[strings.TrimSpace(gw)] = strings.TrimSpace(integration)
	}
	return &v3Sender{
		baseURL:  strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
		timeout:  timeout,
		gateways: gateways,
		http:     httpClient,
		tokens:   tokens,
		logger:   logger,
		slots:    make(chan struct{}, v3MaxInFlight),
	}
}

func (s *v3Sender) integrationFor(gatewayID, collectorID string) (string, bool) {
	integration, ok := s.gateways[gatewayID]
	if !ok {
		return "", false
	}
	if integration == "" {
		integration = strings.TrimSpace(collectorID)
	}
	return integration, integration != ""
}

func (s *v3Sender) send(ctx context.Context, collectorID, traceID string, body GuardRequest) {
	if s == nil {
		return
	}
	integration, ok := s.integrationFor(body.GatewayID, collectorID)
	if !ok {
		return
	}
	gatewayID := body.GatewayID
	if body.Protocol == protocolA2A {
		recordV3Outcome(ctx, gatewayID, v3OutcomeSkipped)
		return
	}
	select {
	case s.slots <- struct{}{}:
	default:
		recordV3Outcome(ctx, gatewayID, v3OutcomeDropped)
		return
	}
	req := toV3Request(body)
	mode := body.FailureMode
	params := tokenParams{baseURL: s.baseURL, collectorID: integration, gatewayID: gatewayID}
	detached := context.WithoutCancel(ctx)
	s.inFlight.Add(1)
	go func() {
		defer s.inFlight.Done()
		defer func() { <-s.slots }()
		defer func() {
			if r := recover(); r != nil {
				s.log(detached, slog.LevelError, "guard v3 copy panicked", slog.Any("panic", r))
			}
		}()
		callCtx, cancel := context.WithTimeout(detached, s.timeout)
		defer cancel()
		start := time.Now()
		err := s.evaluate(callCtx, params, traceID, mode, req)
		recordV3Call(detached, gatewayID, time.Since(start), err)
		if err != nil {
			s.logFailure(detached, gatewayID, err)
		}
	}()
}

func (s *v3Sender) evaluate(ctx context.Context, params tokenParams, traceID, mode string, body v3Request) error {
	payload, err := marshalNoEscape(body)
	if err != nil {
		return fmt.Errorf("guard: marshal request: %w", err)
	}
	token, err := s.tokens.token(ctx, params)
	if err != nil {
		return err
	}
	err = s.post(ctx, token, traceID, mode, payload)
	var status *v3StatusError
	if !errors.As(err, &status) || status.status != http.StatusUnauthorized {
		return err
	}
	s.tokens.invalidate(params)
	if token, err = s.tokens.token(ctx, params); err != nil {
		return err
	}
	return s.post(ctx, token, traceID, mode, payload)
}

func (s *v3Sender) post(ctx context.Context, token, traceID, mode string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+evaluatePath, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("guard: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", contentTypeJSON)
	if traceID != "" {
		req.Header.Set(traceIDHeader, traceID)
	}
	if mode == "" {
		mode = defaultFailureMode
	}
	req.Header.Set(failureModeHeader, mode)
	if deadline, ok := ctx.Deadline(); ok {
		if ms := time.Until(deadline).Milliseconds(); ms > 0 {
			req.Header.Set(evaluateTimeoutHeader, strconv.FormatInt(ms, 10))
		}
	}
	res, err := s.http.Do(req)
	if err != nil {
		return fmt.Errorf("guard: evaluate call: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
	}()
	if res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxLoggedV3ErrorBytes))
	return &v3StatusError{status: res.StatusCode, body: string(raw)}
}

func (s *v3Sender) logFailure(ctx context.Context, gatewayID string, err error) {
	attrs := []any{
		slog.String("plugin", PluginName),
		slog.String("gateway_id", gatewayID),
		slog.String("reason", v3FailureReason(err)),
		slog.String("error", err.Error()),
	}
	var status *v3StatusError
	if errors.As(err, &status) {
		attrs = append(attrs, slog.Int("status", status.status), slog.String("body", status.body))
		if status.status < http.StatusInternalServerError {
			s.log(ctx, slog.LevelWarn, "guard v3 refused the copy", attrs...)
			return
		}
	}
	var rejected *authRejectedError
	if errors.As(err, &rejected) {
		s.log(ctx, slog.LevelWarn, "guard v3 refused the copy", attrs...)
		return
	}
	s.log(ctx, slog.LevelDebug, "guard v3 copy failed", attrs...)
}

func (s *v3Sender) log(ctx context.Context, level slog.Level, msg string, attrs ...any) {
	if s.logger == nil {
		return
	}
	s.logger.Log(ctx, level, msg, attrs...)
}

func (s *v3Sender) wait() {
	if s != nil {
		s.inFlight.Wait()
	}
}
