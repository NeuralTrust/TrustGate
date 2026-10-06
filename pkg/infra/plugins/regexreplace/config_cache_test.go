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

package regexreplace

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigIsParsedOncePerDistinctSettings(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)
	set := settings(targetResponse, cardRule())

	first, err := p.config(set)
	require.NoError(t, err)
	second, err := p.config(settings(targetResponse, cardRule()))
	require.NoError(t, err)

	require.Len(t, first.compiled, 1)
	assert.Same(t, first.compiled[0].re, second.compiled[0].re, "equal settings must share one compiled regexp")

	other, err := p.config(settings(targetResponse, emailRule()))
	require.NoError(t, err)
	assert.NotSame(t, first.compiled[0].re, other.compiled[0].re)
}

func TestConfigCacheDoesNotRememberFailuresAndIsBounded(t *testing.T) {
	t.Parallel()
	p := New(nil, nil)
	bad := map[string]any{"target": targetResponse, "rules": []map[string]any{{"pattern": "(", "replacement": "x"}}}
	_, err := p.config(bad)
	require.Error(t, err)
	_, err = p.config(bad)
	require.Error(t, err, "a policy that does not parse keeps saying so")

	for i := 0; i < maxCachedConfigs+10; i++ {
		_, err := p.config(settings(targetResponse, map[string]any{"pattern": "a" + string(rune('a'+i%26)) + string(rune('A'+i/26%26)) + string(rune('0'+i/676)), "replacement": "x"}))
		require.NoError(t, err)
	}
	p.cfgCache.mu.RLock()
	defer p.cfgCache.mu.RUnlock()
	assert.LessOrEqual(t, len(p.cfgCache.entries), maxCachedConfigs)
}
