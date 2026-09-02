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

// Package playground stores the metrics Event of playground proxy requests in
// Redis so the dashboard can fetch the trace by TraceID (the X-AG-Trace-Id
// echoed in the proxy response).
package playground

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/redis/go-redis/v9"
)

// headerPlaygroundToken mirrors resolver.HeaderPlaygroundToken, duplicated so
// the infra layer does not depend on the api layer.
const headerPlaygroundToken = "x-ag-playground-token"

const traceKeyPrefix = "playground:trace:"

const saveTimeout = 2 * time.Second

// pushTimeout bounds the cross-boundary push of one trace to the control
// plane; it is longer than the local Redis write because it crosses networks,
// but still short enough not to hold a metrics worker hostage.
const pushTimeout = 5 * time.Second

type Store struct {
	rdb       *redis.Client
	enabled   bool
	ttl       time.Duration
	pushURL   string
	pushToken string
	httpc     *http.Client
	logger    *slog.Logger
}

func NewStore(rdb *redis.Client, cfg config.PlaygroundConfig, logger *slog.Logger) *Store {
	return &Store{
		rdb:       rdb,
		enabled:   cfg.TraceStoreEnabled,
		ttl:       cfg.TraceStoreTTL,
		pushURL:   strings.TrimRight(cfg.TracePushURL, "/"),
		pushToken: cfg.TracePushToken,
		httpc:     &http.Client{Timeout: pushTimeout},
		logger:    logger,
	}
}

// Save persists evt under its TraceID when the store is enabled and the request
// carries the playground token. When a push target is configured (hybrid data
// planes), the trace is also pushed to the control-plane store so the dashboard
// can read it from there. Best-effort: failures are logged, not returned.
func (s *Store) Save(ctx context.Context, req *infracontext.RequestContext, evt *events.Event) {
	if s == nil || !s.enabled || req == nil || evt == nil {
		return
	}
	if evt.TraceID == "" || !hasPlaygroundToken(req.Headers) {
		return
	}

	payload, err := json.Marshal(evt)
	if err != nil {
		s.logger.Error("failed to marshal playground trace",
			slog.String("trace_id", evt.TraceID),
			slog.String("error", err.Error()))
		return
	}

	s.writeLocal(ctx, evt.TraceID, payload)
	s.push(ctx, evt.TraceID, payload)
}

// Put persists an already-built playground trace, regardless of request
// headers. It is the write side of the control-plane ingest endpoint that
// hybrid data planes push traces to.
func (s *Store) Put(ctx context.Context, evt *events.Event) error {
	if s == nil || !s.enabled || s.rdb == nil {
		return errors.New("playground trace store: disabled")
	}
	if evt == nil || evt.TraceID == "" {
		return errors.New("playground trace store: event with a trace id is required")
	}
	payload, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("playground trace store: marshal: %w", err)
	}
	writeCtx, cancel := context.WithTimeout(ctx, saveTimeout)
	defer cancel()
	if err := s.rdb.Set(writeCtx, traceKey(evt.TraceID), payload, s.ttl).Err(); err != nil {
		return fmt.Errorf("playground trace store: set: %w", err)
	}
	return nil
}

func (s *Store) writeLocal(ctx context.Context, traceID string, payload []byte) {
	if s.rdb == nil {
		return
	}
	writeCtx, cancel := context.WithTimeout(ctx, saveTimeout)
	defer cancel()
	if err := s.rdb.Set(writeCtx, traceKey(traceID), payload, s.ttl).Err(); err != nil {
		s.logger.Error("failed to store playground trace",
			slog.String("trace_id", traceID),
			slog.String("error", err.Error()))
	}
}

// push PUTs the trace to the configured control-plane ingest endpoint. Only
// playground traces reach this point (Save gates on the playground token), so
// no regular traffic ever crosses the boundary through it.
func (s *Store) push(ctx context.Context, traceID string, payload []byte) {
	if s.pushURL == "" {
		return
	}
	pushCtx, cancel := context.WithTimeout(ctx, pushTimeout)
	defer cancel()

	endpoint := s.pushURL + "/v1/playground/traces/" + traceID
	req, err := http.NewRequestWithContext(pushCtx, http.MethodPut, endpoint, bytes.NewReader(payload))
	if err != nil {
		s.logger.Error("failed to build playground trace push request",
			slog.String("trace_id", traceID),
			slog.String("error", err.Error()))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if s.pushToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.pushToken)
	}

	res, err := s.httpc.Do(req)
	if err != nil {
		s.logger.Error("failed to push playground trace",
			slog.String("trace_id", traceID),
			slog.String("error", err.Error()))
		return
	}
	defer func() {
		_, _ = io.Copy(io.Discard, io.LimitReader(res.Body, 1<<16))
		_ = res.Body.Close()
	}()
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		s.logger.Error("playground trace push rejected",
			slog.String("trace_id", traceID),
			slog.Int("status", res.StatusCode))
	}
}

// Find returns the stored Event for traceID, or (nil, nil) when no trace exists
// (expired or never stored).
func (s *Store) Find(ctx context.Context, traceID string) (*events.Event, error) {
	if s == nil || !s.enabled || s.rdb == nil {
		return nil, nil
	}
	raw, err := s.rdb.Get(ctx, traceKey(traceID)).Bytes()
	if errors.Is(err, redis.Nil) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("playground trace store: get: %w", err)
	}
	var evt events.Event
	if err := json.Unmarshal(raw, &evt); err != nil {
		return nil, fmt.Errorf("playground trace store: decode: %w", err)
	}
	return &evt, nil
}

func traceKey(traceID string) string {
	return traceKeyPrefix + traceID
}

func hasPlaygroundToken(headers map[string][]string) bool {
	for key, values := range headers {
		if strings.EqualFold(key, headerPlaygroundToken) {
			for _, v := range values {
				if v != "" {
					return true
				}
			}
		}
	}
	return false
}

// IsPlaygroundRequest reports whether the proxy request carries a playground token.
func IsPlaygroundRequest(headers map[string][]string) bool {
	return hasPlaygroundToken(headers)
}
