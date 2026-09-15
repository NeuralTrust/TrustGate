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

package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
)

const (
	// contextBytesPerToken is a conservative lower bound used for RUN-1515
	// preflight: English prose is ~4 bytes/token, so 6 bytes/token plus a
	// 1.5× window rejects only requests that clearly cannot fit.
	contextBytesPerToken = 4
	contextRejectFactor  = 6
	contextBase64MinRun  = 1024
)

func (p *providerInvoker) checkContextBudget(ctx context.Context, prep *preparedInvocation) error {
	if p.catalog == nil || prep == nil || prep.capability != capabilityChat {
		return nil
	}
	if prep.providerName == provider.OpenAICompatible {
		return nil
	}
	model, err := p.catalog.FindModel(ctx, prep.providerName, prep.sentModel)
	if err != nil || model == nil || model.ContextWindow <= 0 {
		if err != nil {
			p.logger.Debug("catalog context-window lookup skipped",
				slog.String("provider", prep.providerName),
				slog.String("model", prep.sentModel),
				slog.String("error", err.Error()))
		}
		return nil
	}
	window := model.ContextWindow
	if len(prep.body) <= contextBytesPerToken*window {
		return nil
	}
	textBytes, toolBytes := estimateRequestTextBytes(prep.body)
	estimate := textBytes / contextBytesPerToken
	if textBytes <= contextRejectFactor*window {
		return nil
	}
	p.logger.Info("refusing request that exceeds the model context window",
		slog.String("sent_model", prep.sentModel),
		slog.Int("window", window),
		slog.Int("estimate", estimate))
	toolEstimate := toolBytes / contextBytesPerToken
	return fmt.Errorf("%w: %s/%s accepts %d tokens but the request is ~%d tokens (~%d in tool definitions); remove tools or messages, or route to a model with a larger context",
		ErrContextWindowExceeded, prep.providerName, prep.sentModel, window, estimate, toolEstimate)
}

func estimateRequestTextBytes(body []byte) (total, tools int) {
	if len(body) == 0 {
		return 0, 0
	}
	var parsed any
	if json.Unmarshal(body, &parsed) != nil {
		return countScalarString(string(body)), 0
	}
	total = sumTextBytes(parsed)
	if obj, ok := parsed.(map[string]any); ok {
		tools = sumTextBytes(obj["tools"])
	}
	return total, tools
}

func sumTextBytes(v any) int {
	switch val := v.(type) {
	case string:
		return countScalarString(val)
	case map[string]any:
		n := 0
		for _, child := range val {
			n += sumTextBytes(child)
		}
		return n
	case []any:
		n := 0
		for _, child := range val {
			n += sumTextBytes(child)
		}
		return n
	default:
		return 0
	}
}

func countScalarString(s string) int {
	if s == "" {
		return 0
	}
	if strings.HasPrefix(s, "data:") || looksLikeBase64Blob(s) {
		return 0
	}
	n := 0
	prevSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if prevSpace {
				continue
			}
			prevSpace = true
			n++
			continue
		}
		prevSpace = false
		n += utf8.RuneLen(r)
		if n < 0 {
			n = 0
		}
	}
	return n
}

func looksLikeBase64Blob(s string) bool {
	if len(s) < contextBase64MinRun {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' || c == '/' || c == '=' {
			continue
		}
		return false
	}
	return true
}
