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

package azure

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

const (
	promptCacheRetentionField = "prompt_cache_retention"
	unrecognizedArgument      = "Unrecognized request argument"

	retentionMemoTTL     = time.Hour
	retentionMemoEntries = 1024
)

// retentionMemo remembers the deployment URLs that answered 400 to
// prompt_cache_retention, so the gateway stops sending them a key it mapped
// itself instead of paying a failed round trip on every request (ENG-1618 D5).
type retentionMemo struct {
	ttl       time.Duration
	max       int64
	now       func() time.Time
	entries   sync.Map
	size      atomic.Int64
	saturated atomic.Bool
}

func newRetentionMemo() *retentionMemo {
	return &retentionMemo{ttl: retentionMemoTTL, max: retentionMemoEntries, now: time.Now}
}

func (m *retentionMemo) rejected(url string) bool {
	if m == nil {
		return false
	}
	v, ok := m.entries.Load(url)
	if !ok {
		return false
	}
	if expiry, _ := v.(time.Time); m.now().Before(expiry) {
		return true
	}
	if m.entries.CompareAndDelete(url, v) {
		m.size.Add(-1)
	}
	return false
}

func (m *retentionMemo) remember(url string) {
	if m == nil {
		return
	}
	if _, loaded := m.entries.Swap(url, m.now().Add(m.ttl)); loaded {
		return
	}
	if m.size.Add(1) <= m.max {
		return
	}
	m.evictExpired()
	if m.size.Load() <= m.max {
		return
	}
	if _, ok := m.entries.LoadAndDelete(url); ok {
		m.size.Add(-1)
	}
	if m.saturated.CompareAndSwap(false, true) {
		slog.Info("Azure prompt_cache_retention memo is full; deployments it cannot hold pay the retry until entries expire",
			slog.Int64("entries", m.max))
	}
}

func (m *retentionMemo) evictExpired() {
	now := m.now()
	m.entries.Range(func(k, v any) bool {
		if expiry, _ := v.(time.Time); !now.Before(expiry) && m.entries.CompareAndDelete(k, v) {
			m.size.Add(-1)
		}
		return true
	})
}

// sendableBody drops prompt_cache_retention the gateway mapped into reqBody
// when the deployment already rejected it. A key the client sent itself is
// forwarded as sent.
func (c *client) sendableBody(config *providers.Config, url string, reqBody []byte) []byte {
	if !config.CacheRetentionMapped || !c.retention.rejected(url) {
		return reqBody
	}
	if out, ok := withoutRetention(reqBody); ok {
		return out
	}
	return reqBody
}

// retentionRetryBody returns reqBody without prompt_cache_retention when Azure
// answered 400 naming that field and the gateway, not the client, wrote it:
// the gateway cannot tell from a deployment name whether the model takes it.
func (c *client) retentionRetryBody(ctx context.Context, config *providers.Config, url, deployment string, reqBody []byte, err error) ([]byte, bool) {
	if !config.CacheRetentionMapped || !rejectsRetention(err) {
		return nil, false
	}
	out, ok := withoutRetention(reqBody)
	if !ok {
		return nil, false
	}
	c.retention.remember(url)
	slog.InfoContext(ctx, "retrying Azure request without prompt_cache_retention",
		slog.String("deployment", deployment))
	return out, true
}

// rejectsRetention reports whether err is Azure's 400 for
// prompt_cache_retention. The OpenAI error param names the field when Azure
// fills it; otherwise an "Unrecognized request argument" message, and only
// then any mention of the field in the body, decides.
func rejectsRetention(err error) bool {
	be, ok := registry.IsBackendError(err)
	if !ok || be.StatusCode != http.StatusBadRequest {
		return false
	}
	var envelope struct {
		Error struct {
			Message string `json:"message"`
			Param   string `json:"param"`
		} `json:"error"`
	}
	if json.Unmarshal(be.Body, &envelope) == nil {
		if param := envelope.Error.Param; param != "" {
			return param == promptCacheRetentionField
		}
		if msg := envelope.Error.Message; strings.Contains(msg, unrecognizedArgument) {
			return strings.Contains(msg, promptCacheRetentionField)
		}
	}
	return bytes.Contains(be.Body, []byte(promptCacheRetentionField))
}

func withoutRetention(reqBody []byte) ([]byte, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(reqBody, &fields) != nil {
		return nil, false
	}
	if _, has := fields[promptCacheRetentionField]; !has {
		return nil, false
	}
	delete(fields, promptCacheRetentionField)
	out, err := json.Marshal(fields)
	if err != nil {
		return nil, false
	}
	return out, true
}
