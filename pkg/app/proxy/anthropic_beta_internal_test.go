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
	"fmt"
	"strings"
	"testing"

	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
)

func TestAnthropicBetas(t *testing.T) {
	headers := func(h map[string][]string) *infracontext.RequestContext {
		return &infracontext.RequestContext{Headers: h}
	}

	assert.Empty(t, anthropicBetas(nil))
	assert.Empty(t, anthropicBetas(headers(nil)))
	assert.Empty(t, anthropicBetas(headers(map[string][]string{"X-Other": {"context-management-2025-06-27"}})))

	// Any case of the name, every line, trimmed and de-duplicated, in order.
	assert.Equal(t,
		"context-management-2025-06-27,claude-code-20250219,oauth-2025-04-20",
		anthropicBetas(headers(map[string][]string{
			"anthropic-beta": {" context-management-2025-06-27 ,claude-code-20250219", "oauth-2025-04-20,claude-code-20250219"},
		})),
	)

	// A flag that is not a plain name is dropped, not sent on.
	assert.Equal(t, "files-api-2025-04-14",
		anthropicBetas(headers(map[string][]string{"Anthropic-Beta": {"files-api-2025-04-14,evil\r\nx-api-key: y,,a b"}})))

	// A bounded number of flags.
	many := make([]string, maxAnthropicBetas+5)
	for i := range many {
		many[i] = fmt.Sprintf("beta-%d", i)
	}
	got := anthropicBetas(headers(map[string][]string{"anthropic-beta": {strings.Join(many, ",")}}))
	assert.Len(t, strings.Split(got, ","), maxAnthropicBetas)
}
