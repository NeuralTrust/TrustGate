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
	"net/http"
	"testing"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
)

// The client body is rewritten into the client's dialect, which drops the
// provider's error type. Failover still has to see "not_found_error".
func TestBackendErrorResponse_FailoverReadsTheProviderBody(t *testing.T) {
	t.Parallel()
	be := registrydomain.NewBackendError(http.StatusNotFound, []byte(`{"type":"error","error":{"type":"not_found_error","message":"model: claude-x"}}`))
	prep := &preparedInvocation{sourceFormat: adapter.FormatOpenAI, targetFormat: adapter.FormatAnthropic}

	resp := (&providerInvoker{}).backendErrorResponse(be, &registrydomain.Registry{LLMTarget: &registrydomain.LLMTarget{Provider: "anthropic"}}, prep)

	assert.JSONEq(t, `{"error":{"type":"invalid_request_error","message":"model: claude-x"}}`, string(resp.Body))
	assert.True(t, responseCarriesModelNotFound(resp))
}

func TestProviderWording_FallsBackToTheClientBody(t *testing.T) {
	t.Parallel()
	resp := &ProviderResponse{Body: []byte(`{"error":{"type":"server_error","message":"overloaded"}}`)}

	assert.True(t, responseCarriesProviderError(resp))
	assert.False(t, responseCarriesProviderError(nil))
}
