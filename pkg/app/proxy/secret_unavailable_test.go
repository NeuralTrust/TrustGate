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
	"errors"
	"testing"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
)

func TestMarkedRegistryFailsBeforeAnyUpstreamCall(t *testing.T) {
	t.Parallel()
	reg := &registrydomain.Registry{LLMTarget: &registrydomain.LLMTarget{Provider: "openai"}}
	reg.MarkCredentialUnavailable()
	p := &providerInvoker{}
	req := &infracontext.RequestContext{}
	if _, err := p.Invoke(context.Background(), reg, req); !errors.Is(err, registrydomain.ErrSecretUnavailable) {
		t.Fatalf("Invoke: %v", err)
	}
	if _, err := p.InvokeStream(context.Background(), reg, req); !errors.Is(err, registrydomain.ErrSecretUnavailable) {
		t.Fatalf("InvokeStream: %v", err)
	}
	if got := classifyOutcome(nil, registrydomain.ErrSecretUnavailable, fallbackTriggers{}); got != OutcomeRetryable {
		t.Fatalf("outcome = %v, want retryable so failover can try another registry", got)
	}
	if got := classifyFailure(nil, registrydomain.ErrSecretUnavailable); got != failureHTTP5xx {
		t.Fatalf("failure kind = %v, want the 5xx kind so the fallback chain follows the 5xx trigger", got)
	}
}
