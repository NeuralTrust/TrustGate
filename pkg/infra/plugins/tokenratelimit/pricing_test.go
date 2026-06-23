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

package tokenratelimit

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/assert"
)

func TestBillableInputTokens(t *testing.T) {
	usage := &adapter.CanonicalUsage{InputTokens: 100, CacheReadInputTokens: 30}
	t.Run("excludes cache reads by default", func(t *testing.T) {
		assert.Equal(t, 100, billableInputTokens(&config{}, usage))
	})
	t.Run("includes cache reads when enabled", func(t *testing.T) {
		assert.Equal(t, 130, billableInputTokens(&config{CountCacheReads: true}, usage))
	})
	t.Run("nil usage", func(t *testing.T) {
		assert.Equal(t, 0, billableInputTokens(&config{CountCacheReads: true}, nil))
	})
}
