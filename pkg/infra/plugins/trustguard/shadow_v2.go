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
	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

const (
	defaultAgentSecurityTimeout = 5 * time.Second
	// agentSecurityMaxInFlight bounds the AgentSecurity calls waiting at once. An AgentSecurity that is down
	// or slow would otherwise hold one goroutine and one connection per request
	// for its whole timeout; past the bound a copy is dropped and counted.
	agentSecurityMaxInFlight = 256

	agentSecurityPeerService      = "agentsecurity"
	agentSecurityEvaluateSpanName = "agentsecurity.evaluate"

	maxLoggedAgentSecurityErrorBytes = 512

	// A gateway AgentSecurity refused is not asked again for this long; the cache
	// holds at most agentSecurityRefusedMax gateways so many tenants cannot grow it.
	agentSecurityRefusedTTL = 5 * time.Minute
	agentSecurityRefusedMax = 4096
	// agentSecurityTokenBackoff pauses every copy after a token request fails for any other reason.
	agentSecurityTokenBackoff = 30 * time.Second
)

// AgentSecurityConfig is AgentSecurity, which receives a copy of every
// evaluation of the gateways it lists.
type AgentSecurityConfig struct {
	BaseURL      string
	Timeout      time.Duration
	ClientID     string
	ClientSecret string
	// Gateways maps each gateway that sends to AgentSecurity to the AgentSecurity integration
	// its token names. An empty integration id is the policy's collector_id.
	Gateways map[string]string
	// ShadowAll copies every gateway. Those not in Gateways ask for a token by gateway id
	// alone and AgentSecurity resolves the integration.
	ShadowAll bool
}

func (c AgentSecurityConfig) enabled() bool {
	return strings.TrimSpace(c.BaseURL) != "" &&
		strings.TrimSpace(c.ClientID) != "" &&
		strings.TrimSpace(c.ClientSecret) != "" &&
		(len(c.Gateways) > 0 || c.ShadowAll)
}

// agentSecurityRequest is AgentSecurity's evaluate body. AgentSecurity decodes it strictly and knows no
// v2 name: consumer_id is application_id, and there is no a2a.
type agentSecurityRequest struct {
	OriginalRequest *requestmeta.OriginalRequest `json:"original_request,omitempty"`
	Payload         json.RawMessage              `json:"payload"`
	Direction       string                       `json:"direction"`
	Protocol        string                       `json:"protocol"`
	GatewayID       string                       `json:"gateway_id"`
	SessionID       string                       `json:"session_id,omitempty"`
	ApplicationID   string                       `json:"application_id,omitempty"`
	Attributes      agentSecurityAttributes      `json:"attributes"`
}

type agentSecurityAttributes struct {
	ContentType string                    `json:"content_type"`
	Model       *agentSecurityModel       `json:"model,omitempty"`
	User        *GuardUser                `json:"user,omitempty"`
	Application *agentSecurityApplication `json:"application,omitempty"`
	MCPServer   *agentSecurityMCPServer   `json:"mcp_server,omitempty"`
	Stream      *GuardStream              `json:"stream,omitempty"`
}

type agentSecurityApplication struct {
	Name string `json:"name"`
}

// agentSecurityMCPServer carries AgentSecurity's canonical id of the server: the catalog code, or
// the registry id of a server added by URL.
type agentSecurityMCPServer struct {
	ID   string             `json:"id"`
	Name string             `json:"name,omitempty"`
	Tool *agentSecurityTool `json:"tool,omitempty"`
}

type agentSecurityTool struct {
	Name string `json:"name"`
}

type agentSecurityModel struct {
	Name          string `json:"name,omitempty"`
	Provider      string `json:"provider,omitempty"`
	RequestedName string `json:"requested_name,omitempty"`
}

func toAgentSecurityRequest(body GuardRequest, request *infracontext.RequestContext) agentSecurityRequest {
	req := agentSecurityRequest{
		OriginalRequest: body.OriginalRequest,
		Payload:         append(json.RawMessage(nil), body.Payload...),
		Direction:       body.Direction,
		Protocol:        body.Protocol,
		GatewayID:       body.GatewayID,
		SessionID:       body.SessionID,
		ApplicationID:   strings.TrimSpace(body.ConsumerID),
		Attributes: agentSecurityAttributes{
			ContentType: body.Attributes.ContentType,
			User:        body.Attributes.User,
			MCPServer:   agentSecurityMCPServerOf(body.Attributes.MCPServer),
			Stream:      body.Attributes.Stream,
		},
	}
	if request != nil {
		if !request.MCP {
			req.Attributes.Model = agentSecurityModelOf(request, body.Direction)
		} else if server := req.Attributes.MCPServer; server != nil {
			server.Name = strings.TrimSpace(request.MCPServerName)
			if tool := strings.TrimSpace(request.MCPTool); tool != "" {
				server.Tool = &agentSecurityTool{Name: tool}
			}
		}
	}
	if c := body.Attributes.Consumer; c != nil && c.Name != "" {
		req.Attributes.Application = &agentSecurityApplication{Name: c.Name}
	}
	return req
}

func agentSecurityModelOf(req *infracontext.RequestContext, direction string) *agentSecurityModel {
	name := strings.TrimSpace(req.ResolvedModel)
	if name == "" && direction == directionOutput {
		name = strings.TrimSpace(req.SentModel)
	}
	if name == "" {
		if req.IsBedrockNative() {
			name = req.BedrockNative.ModelID
		} else {
			if model, err := adapter.ExtractModel(req.Body); err == nil {
				name = model
			}
			if name == "" {
				name = req.DefaultModel
			}
		}
	}
	name = strings.TrimSpace(name)
	if arn, ok := bedrocknative.ParseBedrockARN(name); ok {
		name, _ = arn.ModelID()
	}
	if strings.Contains(name, "@") || strings.HasPrefix(strings.ToLower(name), "pool:") ||
		strings.HasPrefix(strings.ToLower(name), "arn:") || strings.EqualFold(name, "auto") {
		name = ""
	}
	return &agentSecurityModel{
		Name:          name,
		Provider:      strings.ToLower(strings.TrimSpace(req.Provider)),
		RequestedName: req.RequestedModel,
	}
}

func agentSecurityMCPServerOf(server *GuardMCPServer) *agentSecurityMCPServer {
	if server == nil {
		return nil
	}
	if server.Code != "" {
		return &agentSecurityMCPServer{ID: server.Code}
	}
	return &agentSecurityMCPServer{ID: server.ID}
}

type agentSecurityStatusError struct {
	status int
	body   string
}

func (e *agentSecurityStatusError) Error() string {
	return fmt.Sprintf("agentsecurity: evaluate status %d", e.status)
}

// agentSecuritySender sends AgentSecurity its copy of an evaluation. Nothing it does reaches the
// request: the call runs detached, under its own timeout, and its outcome is
// only logged and counted.
type agentSecuritySender struct {
	baseURL  string
	timeout  time.Duration
	gateways map[string]string
	all      bool
	http     *http.Client
	tokens   *tokenManager
	logger   *slog.Logger

	slots    chan struct{}
	inFlight sync.WaitGroup

	now       func() time.Time
	refusedMu sync.Mutex
	refused   map[string]refusal
	// tokenBackoffUntil is guarded by refusedMu.
	tokenBackoffUntil time.Time
}

type refusal struct {
	until time.Time
	code  string
}

func newAgentSecuritySender(cfg AgentSecurityConfig, base http.RoundTripper, logger *slog.Logger) *agentSecuritySender {
	if !cfg.enabled() {
		if (len(cfg.Gateways) > 0 || cfg.ShadowAll) && logger != nil {
			logger.Warn("AgentSecurity copies are off: base URL or client credentials missing",
				slog.Int("gateways", len(cfg.Gateways)), slog.Bool("shadow_all", cfg.ShadowAll))
		}
		return nil
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultAgentSecurityTimeout
	}
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: o11y.InternalTransportOver(base, agentSecurityPeerService, agentSecurityEvaluateSpanName),
	}
	tokens := newTokenManager(httpClient, cfg.ClientID, cfg.ClientSecret)
	tokens.agentSecurity = true
	gateways := make(map[string]string, len(cfg.Gateways))
	for gw, integration := range cfg.Gateways {
		gateways[strings.TrimSpace(gw)] = strings.TrimSpace(integration)
	}
	return &agentSecuritySender{
		baseURL:  strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
		timeout:  timeout,
		gateways: gateways,
		all:      cfg.ShadowAll,
		now:      time.Now,
		refused:  make(map[string]refusal),
		http:     httpClient,
		tokens:   tokens,
		logger:   logger,
		slots:    make(chan struct{}, agentSecurityMaxInFlight),
	}
}

func (s *agentSecuritySender) integrationFor(gatewayID, collectorID string) (string, bool) {
	integration, ok := s.gateways[gatewayID]
	if !ok {
		return "", s.all
	}
	if integration == "" {
		integration = strings.TrimSpace(collectorID)
	}
	return integration, integration != "" || s.all
}

// isRefused returns the refusal code AgentSecurity gave gatewayID, while it is cached.
func (s *agentSecuritySender) isRefused(gatewayID string) (string, bool) {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	r, ok := s.refused[gatewayID]
	if ok && s.now().Before(r.until) {
		return r.code, true
	}
	if ok {
		delete(s.refused, gatewayID)
	}
	return "", false
}

// markRefused caches the refusal and reports whether it is new, so the caller warns once.
// At the cap it sweeps expired entries, then evicts the earliest expiry.
func (s *agentSecuritySender) markRefused(gatewayID, code string) bool {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	now := s.now()
	if r, ok := s.refused[gatewayID]; ok && now.Before(r.until) {
		return false
	}
	if _, ok := s.refused[gatewayID]; !ok && len(s.refused) >= agentSecurityRefusedMax {
		oldest, oldestAt := "", time.Time{}
		for gw, r := range s.refused {
			if !now.Before(r.until) {
				delete(s.refused, gw)
			} else if oldest == "" || r.until.Before(oldestAt) {
				oldest, oldestAt = gw, r.until
			}
		}
		if len(s.refused) >= agentSecurityRefusedMax {
			delete(s.refused, oldest)
		}
	}
	s.refused[gatewayID] = refusal{until: now.Add(agentSecurityRefusedTTL), code: code}
	return true
}

func recordRefusal(ctx context.Context, code string) {
	if code == codeAmbiguousGateway {
		recordAgentSecurityOutcome(ctx, agentSecurityOutcomeAmbiguousGateway)
		return
	}
	recordAgentSecurityOutcome(ctx, agentSecurityOutcomeUnknownGateway)
}

// handleRefusal skips a gateway AgentSecurity refused at the token step. It reports
// whether err was one.
func (s *agentSecuritySender) handleRefusal(ctx context.Context, gatewayID string, err error) bool {
	var refused *gatewayRefusedError
	if !errors.As(err, &refused) {
		return false
	}
	fresh := s.markRefused(gatewayID, refused.code)
	recordRefusal(ctx, refused.code)
	if !fresh {
		return true
	}
	if refused.code == codeAmbiguousGateway {
		s.log(ctx, slog.LevelWarn, "AgentSecurity cannot pick an integration for the gateway; copies skipped",
			slog.String("plugin", PluginName), slog.String("gateway_id", gatewayID))
	} else {
		s.log(ctx, slog.LevelDebug, "AgentSecurity does not know the gateway; copies skipped",
			slog.String("plugin", PluginName), slog.String("gateway_id", gatewayID))
	}
	return true
}

// inTokenBackoff reports whether a recent token failure pauses all copies.
func (s *agentSecuritySender) inTokenBackoff() bool {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	return s.now().Before(s.tokenBackoffUntil)
}

// startTokenBackoff pauses copies after a token failure and reports whether it began
// a new pause, so the caller warns once per interval.
func (s *agentSecuritySender) startTokenBackoff() bool {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	now := s.now()
	if now.Before(s.tokenBackoffUntil) {
		return false
	}
	s.tokenBackoffUntil = now.Add(agentSecurityTokenBackoff)
	return true
}

func (s *agentSecuritySender) send(ctx context.Context, collectorID, traceID string, body GuardRequest, request *infracontext.RequestContext) {
	if s == nil {
		return
	}
	integration, ok := s.integrationFor(body.GatewayID, collectorID)
	if !ok {
		return
	}
	gatewayID := body.GatewayID
	if body.Protocol == protocolA2A {
		recordAgentSecurityOutcome(ctx, agentSecurityOutcomeSkipped)
		return
	}
	if code, refused := s.isRefused(gatewayID); refused {
		recordRefusal(ctx, code)
		return
	}
	if s.inTokenBackoff() {
		recordAgentSecurityOutcome(ctx, agentSecurityOutcomeTokenBackoff)
		return
	}
	select {
	case s.slots <- struct{}{}:
	default:
		recordAgentSecurityOutcome(ctx, agentSecurityOutcomeDropped)
		return
	}
	req := toAgentSecurityRequest(body, request)
	mode := body.FailureMode
	params := tokenParams{baseURL: s.baseURL, collectorID: integration, gatewayID: gatewayID}
	detached := context.WithoutCancel(ctx)
	s.inFlight.Add(1)
	go func() {
		defer s.inFlight.Done()
		defer func() { <-s.slots }()
		defer func() {
			if r := recover(); r != nil {
				s.log(detached, slog.LevelError, "AgentSecurity copy panicked", slog.Any("panic", r))
			}
		}()
		callCtx, cancel := context.WithTimeout(detached, s.timeout)
		defer cancel()
		start := time.Now()
		err := s.evaluate(callCtx, params, traceID, mode, req)
		if s.handleRefusal(detached, gatewayID, err) {
			return
		}
		recordAgentSecurityCall(detached, time.Since(start), err)
		if err != nil {
			s.logFailure(detached, gatewayID, err)
		}
	}()
}

func (s *agentSecuritySender) evaluate(ctx context.Context, params tokenParams, traceID, mode string, body agentSecurityRequest) error {
	payload, err := marshalNoEscape(body)
	if err != nil {
		return fmt.Errorf("agentsecurity: marshal request: %w", err)
	}
	token, err := s.tokens.token(ctx, params)
	if err != nil {
		s.tokenFailed(ctx, params.gatewayID, err)
		return err
	}
	err = s.post(ctx, token, traceID, mode, payload)
	var status *agentSecurityStatusError
	if !errors.As(err, &status) || status.status != http.StatusUnauthorized {
		return err
	}
	s.tokens.invalidate(params)
	if token, err = s.tokens.token(ctx, params); err != nil {
		s.tokenFailed(ctx, params.gatewayID, err)
		return err
	}
	return s.post(ctx, token, traceID, mode, payload)
}

// tokenFailed pauses copies after a token failure that is not a typed gateway refusal.
func (s *agentSecuritySender) tokenFailed(ctx context.Context, gatewayID string, err error) {
	var refused *gatewayRefusedError
	if errors.As(err, &refused) || errors.Is(err, context.Canceled) {
		return
	}
	if s.startTokenBackoff() {
		s.log(ctx, slog.LevelWarn, "AgentSecurity token request failed; copies paused",
			slog.String("plugin", PluginName), slog.String("gateway_id", gatewayID),
			slog.Duration("backoff", agentSecurityTokenBackoff), slog.String("error", err.Error()))
	}
}

func (s *agentSecuritySender) post(ctx context.Context, token, traceID, mode string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+evaluatePath, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("agentsecurity: build request: %w", err)
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
		return fmt.Errorf("agentsecurity: evaluate call: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
	}()
	if res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxLoggedAgentSecurityErrorBytes))
	return &agentSecurityStatusError{status: res.StatusCode, body: string(raw)}
}

func (s *agentSecuritySender) logFailure(ctx context.Context, gatewayID string, err error) {
	attrs := []any{
		slog.String("plugin", PluginName),
		slog.String("gateway_id", gatewayID),
		slog.String("reason", agentSecurityFailureReason(err)),
		slog.String("error", err.Error()),
	}
	var status *agentSecurityStatusError
	if errors.As(err, &status) {
		attrs = append(attrs, slog.Int("status", status.status), slog.String("body", status.body))
		if status.status < http.StatusInternalServerError {
			s.log(ctx, slog.LevelWarn, "AgentSecurity refused the copy", attrs...)
			return
		}
	}
	var rejected *authRejectedError
	if errors.As(err, &rejected) {
		s.log(ctx, slog.LevelWarn, "AgentSecurity refused the copy", attrs...)
		return
	}
	s.log(ctx, slog.LevelDebug, "AgentSecurity copy failed", attrs...)
}

func (s *agentSecuritySender) log(ctx context.Context, level slog.Level, msg string, attrs ...any) {
	if s.logger == nil {
		return
	}
	s.logger.Log(ctx, level, msg, attrs...)
}

func (s *agentSecuritySender) wait() {
	if s != nil {
		s.inFlight.Wait()
	}
}
