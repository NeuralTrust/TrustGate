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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

func TestUpstreamHeadersDropReferences(t *testing.T) {
	t.Parallel()
	got := upstreamHeaders(
		providers.Credentials{Headers: map[string]string{"X-Cred": "secret://vault/ai/k", "X-Ok": "v"}},
		providers.OpenAICompatibleOptions{Headers: map[string]string{"X-Org": "SECRET://vault/ai/org", "X-Lit": "literal"}},
	)
	if len(got) != 2 || got["X-Ok"] != "v" || got["X-Lit"] != "literal" {
		t.Fatalf("headers = %v", got)
	}
}
