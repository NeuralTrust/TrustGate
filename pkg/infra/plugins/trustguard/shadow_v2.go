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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/o11y"
)

const (
	defaultV2ShadowTimeout = 5 * time.Second
	// v2ShadowMaxInFlight bounds the TrustGuard v2 calls waiting at once. A TrustGuard v2 that is down
	// or slow would otherwise hold one goroutine and one connection per request
	// for its whole timeout; past the bound a copy is dropped and counted.
	v2ShadowMaxInFlight = 256

	v2ShadowPeerService      = peerService
	v2ShadowEvaluateSpanName = v2EvaluateSpanName

	maxLoggedV2ErrorBytes = 512

	// A gateway TrustGuard v2 refused is not asked again for this long; the cache
	// holds at most v2ShadowRefusedMax gateways so many tenants cannot grow it.
	v2ShadowRefusedTTL = 5 * time.Minute
	v2ShadowRefusedMax = 4096
	// v2ShadowTokenBackoff pauses every copy after a token request fails for any other reason.
	v2ShadowTokenBackoff = 30 * time.Second
)

// V2ShadowConfig is TrustGuard v2, which receives a copy of every
// evaluation of the gateways it lists.
type V2ShadowConfig struct {
	BaseURL      string
	Timeout      time.Duration
	ClientID     string
	ClientSecret string
	// Gateways maps each gateway that sends to TrustGuard v2 to the TrustGuard v2 integration
	// its token names. An empty integration id is the policy's collector_id.
	Gateways map[string]string
	// ShadowAll copies every gateway. Those not in Gateways ask for a token by gateway id
	// alone and TrustGuard v2 resolves the integration.
	ShadowAll bool
}

func (c V2ShadowConfig) enabled() bool {
	return strings.TrimSpace(c.BaseURL) != "" &&
		strings.TrimSpace(c.ClientID) != "" &&
		strings.TrimSpace(c.ClientSecret) != "" &&
		(len(c.Gateways) > 0 || c.ShadowAll)
}

type v2ShadowStatusError struct {
	status int
	body   string
}

func (e *v2ShadowStatusError) Error() string {
	return fmt.Sprintf("trustguard v2: evaluate status %d", e.status)
}

// v2ShadowSender sends TrustGuard v2 its copy of an evaluation. Nothing it does reaches the
// request: the call runs detached, under its own timeout, and its outcome is
// only logged and counted.
type v2ShadowSender struct {
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

func newV2ShadowSender(cfg V2ShadowConfig, base http.RoundTripper, logger *slog.Logger) *v2ShadowSender {
	if !cfg.enabled() {
		if (len(cfg.Gateways) > 0 || cfg.ShadowAll) && logger != nil {
			logger.Warn("TrustGuard v2 copies are off: base URL or client credentials missing",
				slog.Int("gateways", len(cfg.Gateways)), slog.Bool("shadow_all", cfg.ShadowAll))
		}
		return nil
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultV2ShadowTimeout
	}
	httpClient := &http.Client{
		Timeout:   timeout,
		Transport: o11y.InternalTransportOver(base, v2ShadowPeerService, v2ShadowEvaluateSpanName),
	}
	tokens := newTokenManager(httpClient, cfg.ClientID, cfg.ClientSecret)
	tokens.useV2()
	gateways := make(map[string]string, len(cfg.Gateways))
	for gw, integration := range cfg.Gateways {
		gateways[strings.TrimSpace(gw)] = strings.TrimSpace(integration)
	}
	return &v2ShadowSender{
		baseURL:  strings.TrimRight(strings.TrimSpace(cfg.BaseURL), "/"),
		timeout:  timeout,
		gateways: gateways,
		all:      cfg.ShadowAll,
		now:      time.Now,
		refused:  make(map[string]refusal),
		http:     httpClient,
		tokens:   tokens,
		logger:   logger,
		slots:    make(chan struct{}, v2ShadowMaxInFlight),
	}
}

func (s *v2ShadowSender) integrationFor(gatewayID, collectorID string) (string, bool) {
	integration, ok := s.gateways[gatewayID]
	if !ok {
		return "", s.all
	}
	if integration == "" {
		integration = strings.TrimSpace(collectorID)
	}
	return integration, integration != "" || s.all
}

// isRefused returns the refusal code TrustGuard v2 gave gatewayID, while it is cached.
func (s *v2ShadowSender) isRefused(gatewayID string) (string, bool) {
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
func (s *v2ShadowSender) markRefused(gatewayID, code string) bool {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	now := s.now()
	if r, ok := s.refused[gatewayID]; ok && now.Before(r.until) {
		return false
	}
	if _, ok := s.refused[gatewayID]; !ok && len(s.refused) >= v2ShadowRefusedMax {
		oldest, oldestAt := "", time.Time{}
		for gw, r := range s.refused {
			if !now.Before(r.until) {
				delete(s.refused, gw)
			} else if oldest == "" || r.until.Before(oldestAt) {
				oldest, oldestAt = gw, r.until
			}
		}
		if len(s.refused) >= v2ShadowRefusedMax {
			delete(s.refused, oldest)
		}
	}
	s.refused[gatewayID] = refusal{until: now.Add(v2ShadowRefusedTTL), code: code}
	return true
}

func recordRefusal(ctx context.Context, code string) {
	if code == codeAmbiguousGateway {
		recordV2ShadowOutcome(ctx, v2ShadowOutcomeAmbiguousGateway)
		return
	}
	recordV2ShadowOutcome(ctx, v2ShadowOutcomeUnknownGateway)
}

// handleRefusal skips a gateway TrustGuard v2 refused at the token step. It reports
// whether err was one.
func (s *v2ShadowSender) handleRefusal(ctx context.Context, gatewayID string, err error) bool {
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
		s.log(ctx, slog.LevelWarn, "TrustGuard v2 cannot pick an integration for the gateway; copies skipped",
			slog.String("plugin", PluginName), slog.String("gateway_id", gatewayID))
	} else {
		s.log(ctx, slog.LevelDebug, "TrustGuard v2 does not know the gateway; copies skipped",
			slog.String("plugin", PluginName), slog.String("gateway_id", gatewayID))
	}
	return true
}

// inTokenBackoff reports whether a recent token failure pauses all copies.
func (s *v2ShadowSender) inTokenBackoff() bool {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	return s.now().Before(s.tokenBackoffUntil)
}

// startTokenBackoff pauses copies after a token failure and reports whether it began
// a new pause, so the caller warns once per interval.
func (s *v2ShadowSender) startTokenBackoff() bool {
	s.refusedMu.Lock()
	defer s.refusedMu.Unlock()
	now := s.now()
	if now.Before(s.tokenBackoffUntil) {
		return false
	}
	s.tokenBackoffUntil = now.Add(v2ShadowTokenBackoff)
	return true
}

func (s *v2ShadowSender) send(ctx context.Context, collectorID, traceID string, body GuardRequest, request *infracontext.RequestContext) {
	if s == nil {
		return
	}
	integration, ok := s.integrationFor(body.GatewayID, collectorID)
	if !ok {
		return
	}
	gatewayID := body.GatewayID
	if body.Protocol == protocolA2A {
		recordV2ShadowOutcome(ctx, v2ShadowOutcomeSkipped)
		return
	}
	if code, refused := s.isRefused(gatewayID); refused {
		recordRefusal(ctx, code)
		return
	}
	if s.inTokenBackoff() {
		recordV2ShadowOutcome(ctx, v2ShadowOutcomeTokenBackoff)
		return
	}
	select {
	case s.slots <- struct{}{}:
	default:
		recordV2ShadowOutcome(ctx, v2ShadowOutcomeDropped)
		return
	}
	req := toV2Request(body, request)
	mode := body.FailureMode
	params := tokenParams{baseURL: s.baseURL, collectorID: integration, gatewayID: gatewayID}
	detached := context.WithoutCancel(ctx)
	s.inFlight.Add(1)
	go func() {
		defer s.inFlight.Done()
		defer func() { <-s.slots }()
		defer func() {
			if r := recover(); r != nil {
				s.log(detached, slog.LevelError, "TrustGuard v2 copy panicked", slog.Any("panic", r))
			}
		}()
		callCtx, cancel := context.WithTimeout(detached, s.timeout)
		defer cancel()
		start := time.Now()
		err := s.evaluate(callCtx, params, traceID, mode, req)
		if s.handleRefusal(detached, gatewayID, err) {
			return
		}
		recordV2ShadowCall(detached, time.Since(start), err)
		if err != nil {
			s.logFailure(detached, gatewayID, err)
		}
	}()
}

func (s *v2ShadowSender) evaluate(ctx context.Context, params tokenParams, traceID, mode string, body v2Request) error {
	payload, err := marshalNoEscape(body)
	if err != nil {
		return fmt.Errorf("trustguard v2: marshal request: %w", err)
	}
	token, err := s.tokens.token(ctx, params)
	if err != nil {
		s.tokenFailed(ctx, params.gatewayID, err)
		return err
	}
	err = s.post(ctx, token, traceID, mode, payload)
	var status *v2ShadowStatusError
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
func (s *v2ShadowSender) tokenFailed(ctx context.Context, gatewayID string, err error) {
	var refused *gatewayRefusedError
	if errors.As(err, &refused) || errors.Is(err, context.Canceled) {
		return
	}
	if s.startTokenBackoff() {
		s.log(ctx, slog.LevelWarn, "TrustGuard v2 token request failed; copies paused",
			slog.String("plugin", PluginName), slog.String("gateway_id", gatewayID),
			slog.Duration("backoff", v2ShadowTokenBackoff), slog.String("error", err.Error()))
	}
}

func (s *v2ShadowSender) post(ctx context.Context, token, traceID, mode string, payload []byte) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.baseURL+v2EvaluatePath, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("trustguard v2: build request: %w", err)
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
		return fmt.Errorf("trustguard v2: evaluate call: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, maxResponseBytes))
		_ = res.Body.Close()
	}()
	if res.StatusCode >= http.StatusOK && res.StatusCode < http.StatusMultipleChoices {
		return nil
	}
	raw, _ := io.ReadAll(io.LimitReader(res.Body, maxLoggedV2ErrorBytes))
	return &v2ShadowStatusError{status: res.StatusCode, body: string(raw)}
}

func (s *v2ShadowSender) logFailure(ctx context.Context, gatewayID string, err error) {
	attrs := []any{
		slog.String("plugin", PluginName),
		slog.String("gateway_id", gatewayID),
		slog.String("reason", v2ShadowFailureReason(err)),
		slog.String("error", err.Error()),
	}
	var status *v2ShadowStatusError
	if errors.As(err, &status) {
		attrs = append(attrs, slog.Int("status", status.status), slog.String("body", status.body))
		if status.status < http.StatusInternalServerError {
			s.log(ctx, slog.LevelWarn, "TrustGuard v2 refused the copy", attrs...)
			return
		}
	}
	var rejected *authRejectedError
	if errors.As(err, &rejected) {
		s.log(ctx, slog.LevelWarn, "TrustGuard v2 refused the copy", attrs...)
		return
	}
	s.log(ctx, slog.LevelDebug, "TrustGuard v2 copy failed", attrs...)
}

func (s *v2ShadowSender) log(ctx context.Context, level slog.Level, msg string, attrs ...any) {
	if s.logger == nil {
		return
	}
	s.logger.Log(ctx, level, msg, attrs...)
}

func (s *v2ShadowSender) wait() {
	if s != nil {
		s.inFlight.Wait()
	}
}
