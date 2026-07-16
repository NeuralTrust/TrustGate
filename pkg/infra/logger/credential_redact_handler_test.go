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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

func TestCredentialRedactHandler_ScrubsAnyErrorAttrs(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	log := slog.New(NewCredentialRedactHandler(base))

	log.Error("request failed", slog.Any("error", errors.New("Authorization: Bearer sk-live-secret")))

	out := buf.String()
	if strings.Contains(out, "sk-live-secret") {
		t.Fatalf("secret leaked in log output: %s", out)
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &obj); err != nil {
		t.Fatalf("invalid json log: %v", err)
	}
	errVal, _ := obj["error"].(string)
	if !strings.Contains(errVal, "[REDACTED]") {
		t.Fatalf("error attr not redacted: %q", errVal)
	}
}

func TestCredentialRedactHandler_PreservesNonErrorAnyAttrs(t *testing.T) {
	var buf bytes.Buffer
	base := slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelInfo})
	log := slog.New(NewCredentialRedactHandler(base))

	log.Info("status", slog.Any("count", 42), slog.Any("error", nil))

	out := buf.String()
	if !strings.Contains(out, `"count":42`) {
		t.Fatalf("non-error Any attr altered: %s", out)
	}
}

func TestCredentialRedactHandler_EnabledDelegates(t *testing.T) {
	h := NewCredentialRedactHandler(slog.NewTextHandler(ioDiscard{}, &slog.HandlerOptions{Level: slog.LevelError}))
	if !h.Enabled(context.Background(), slog.LevelError) {
		t.Fatal("expected handler to be enabled at error level")
	}
}

type ioDiscard struct{}

func (ioDiscard) Write(p []byte) (int, error) { return len(p), nil }
