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

package catalog

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport/configsynctest"
	"github.com/NeuralTrust/TrustGate/pkg/infra/catalog/modelsdev"
)

func newSignalTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestSyncer_Sync_SignalsOnSuccess(t *testing.T) {
	t.Parallel()
	const payload = `{
		"openai": {
			"id": "openai",
			"name": "OpenAI",
			"models": {
				"gpt-4o": {"id":"gpt-4o","name":"GPT-4o","limit":{"context":128000,"output":16384},"cost":{"input":2.5,"output":10}}
			}
		}
	}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, payload)
	}))
	defer srv.Close()

	signaler := &configsynctest.FakeSignaler{}
	s := NewSyncer(newFakeRepo(), modelsdev.NewClient(srv.URL), newSignalTestLogger(), signaler)

	if err := s.Sync(context.Background()); err != nil {
		t.Fatalf("Sync error: %v", err)
	}
	if got := signaler.Count(); got != 1 {
		t.Fatalf("Signal count = %d, want 1", got)
	}
}

func TestSyncer_Sync_DoesNotSignalOnFailure(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()

	signaler := &configsynctest.FakeSignaler{}
	s := NewSyncer(newFakeRepo(), modelsdev.NewClient(srv.URL), newSignalTestLogger(), signaler)

	if err := s.Sync(context.Background()); err == nil {
		t.Fatal("expected error from failing client")
	}
	if got := signaler.Count(); got != 0 {
		t.Fatalf("Signal count = %d, want 0", got)
	}
}
