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

// Package playground stores the metrics Event of playground-originated proxy
// requests in Redis so the dashboard can fetch the trace it just produced,
// keyed by TraceID (the X-Request-Id echoed in the proxy response).
package playground

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
	infracontext "github.com/NeuralTrust/AgentGateway/pkg/infra/context"
	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
	"github.com/go-redis/redis/v8"
)

// headerPlaygroundToken marks a request as originating from the dashboard
// playground. It mirrors resolver.HeaderPlaygroundToken; duplicated here so the
// infra layer does not depend on the api layer.
const headerPlaygroundToken = "x-ag-playground-token"

const traceKeyPrefix = "playground:trace:"

// saveTimeout bounds the Redis write so a slow store never blocks the metrics
// worker goroutine.
const saveTimeout = 2 * time.Second

type Store struct {
	rdb     *redis.Client
	enabled bool
	ttl     time.Duration
	logger  *slog.Logger
}

func NewStore(rdb *redis.Client, cfg config.PlaygroundConfig, logger *slog.Logger) *Store {
	return &Store{
		rdb:     rdb,
		enabled: cfg.TraceStoreEnabled,
		ttl:     cfg.TraceStoreTTL,
		logger:  logger,
	}
}

// Save persists evt under its TraceID when the store is enabled and the request
// carries the playground token. It is best-effort: failures are logged, never
// returned, so telemetry export is unaffected.
func (s *Store) Save(ctx context.Context, req *infracontext.RequestContext, evt *events.Event) {
	if s == nil || !s.enabled || s.rdb == nil || req == nil || evt == nil {
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

	writeCtx, cancel := context.WithTimeout(ctx, saveTimeout)
	defer cancel()
	if err := s.rdb.Set(writeCtx, traceKey(evt.TraceID), payload, s.ttl).Err(); err != nil {
		s.logger.Error("failed to store playground trace",
			slog.String("trace_id", evt.TraceID),
			slog.String("error", err.Error()))
	}
}

// Find returns the stored Event for traceID, or (nil, nil) when no trace exists
// (expired or never stored).
func (s *Store) Find(ctx context.Context, traceID string) (*events.Event, error) {
	if s.rdb == nil {
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
