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

package azurecontentsafety

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

// endpoint is a tenant policy setting: the client must not carry the
// Ocp-Apim-Subscription-Key to a private address.
func TestAnalyzeRefusesPrivateEndpoint(t *testing.T) {
	providers.SetAllowPrivateNetworks(false)
	t.Cleanup(func() { providers.SetAllowPrivateNetworks(true) })

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	t.Cleanup(srv.Close)

	for _, endpoint := range []string{srv.URL, "http://169.254.169.254/", "http://10.0.0.7/"} {
		_, err := newClient().Analyze(context.Background(), endpoint, "secret", analyzeRequest{Text: "hi"})
		if !errors.Is(err, netguard.ErrBlockedDestination) {
			t.Fatalf("%s: err = %v, want ErrBlockedDestination", endpoint, err)
		}
	}
	if hits.Load() != 0 {
		t.Fatalf("private endpoint received %d request(s)", hits.Load())
	}
}
