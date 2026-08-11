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

package logger

import (
	"context"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/infra/logredact"
)

// CredentialRedactHandler redacts credential-shaped substrings from slog records.
type CredentialRedactHandler struct {
	handler slog.Handler
}

// NewCredentialRedactHandler wraps h so messages and string attrs are scrubbed.
func NewCredentialRedactHandler(h slog.Handler) *CredentialRedactHandler {
	return &CredentialRedactHandler{handler: h}
}

func (h *CredentialRedactHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.handler.Enabled(ctx, level)
}

func (h *CredentialRedactHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Message = logredact.RedactLogString(r.Message)
	cloned := slog.Record{
		Time:    r.Time,
		Level:   r.Level,
		Message: r.Message,
		PC:      r.PC,
	}
	r.Attrs(func(a slog.Attr) bool {
		cloned.AddAttrs(redactAttr(a))
		return true
	})
	return h.handler.Handle(ctx, cloned)
}

func (h *CredentialRedactHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	redacted := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		redacted[i] = redactAttr(a)
	}
	return NewCredentialRedactHandler(h.handler.WithAttrs(redacted))
}

func (h *CredentialRedactHandler) WithGroup(name string) slog.Handler {
	return NewCredentialRedactHandler(h.handler.WithGroup(name))
}

func redactAttr(a slog.Attr) slog.Attr {
	switch a.Value.Kind() {
	case slog.KindAny:
		if err, ok := a.Value.Any().(error); ok && err != nil {
			return slog.String(a.Key, logredact.RedactLogString(err.Error()))
		}
		return a
	case slog.KindString:
		return slog.String(a.Key, logredact.RedactLogString(a.Value.String()))
	case slog.KindGroup:
		g := a.Value.Group()
		for i := range g {
			g[i] = redactAttr(g[i])
		}
		return slog.Attr{Key: a.Key, Value: slog.GroupValue(g...)}
	default:
		return a
	}
}
