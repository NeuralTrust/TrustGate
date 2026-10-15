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

package openaicompat

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// A registry whose base_url points at a private address must fail with a clear
// provider error that names the host, and the upstream must never be dialled.
func TestCompletionsRefusesPrivateBaseURL(t *testing.T) {
	providers.SetAllowPrivateNetworks(false)
	t.Cleanup(func() { providers.SetAllowPrivateNetworks(true) })

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)

	for _, baseURL := range []string{srv.URL, "http://169.254.169.254/v1", "http://10.1.2.3:8000/v1"} {
		cfg := &providers.Config{
			Credentials: providers.Credentials{ApiKey: "sk-test"},
			Options:     map[string]any{"base_url": baseURL},
		}
		_, err := NewClient().Completions(context.Background(), cfg, []byte(`{"model":"m"}`))
		if !errors.Is(err, netguard.ErrBlockedDestination) {
			t.Fatalf("%s: err = %v, want ErrBlockedDestination", baseURL, err)
		}
		host := strings.Split(strings.Split(baseURL, "/")[2], ":")[0]
		if !strings.Contains(err.Error(), host) {
			t.Fatalf("%s: error %q does not name the host", baseURL, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("private upstream received %d request(s)", hits.Load())
	}
}
