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

package plugins_test

import (
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type retiringStub struct {
	appplugins.Plugin
	paths []string
}

func (s retiringStub) RetiredSettings() []string { return s.paths }

func stripRegistry(t *testing.T, paths []string) appplugins.Registry {
	t.Helper()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().Get("retiring").Return(retiringStub{Plugin: pluginmocks.NewPlugin(t), paths: paths}, true).Maybe()
	reg.EXPECT().Get("plain").Return(pluginmocks.NewPlugin(t), true).Maybe()
	reg.EXPECT().Get("unknown").Return(nil, false).Maybe()
	return reg
}

func TestStripRetiredSettings(t *testing.T) {
	reg := stripRegistry(t, []string{"on_error", "streaming.on_error"})
	input := func() map[string]any {
		return map[string]any{
			"keep":      1,
			"On_Error":  "fail_closed",
			"Streaming": map[string]any{"enabled": true, "ON_ERROR": "fail_closed"},
		}
	}

	t.Run("drops keys at every level whatever their case", func(t *testing.T) {
		got := appplugins.StripRetiredSettings(reg, "retiring", input())
		assert.Equal(t, map[string]any{"keep": 1, "Streaming": map[string]any{"enabled": true}}, got)
	})

	t.Run("never edits the settings it is given", func(t *testing.T) {
		in := input()
		_ = appplugins.StripRetiredSettings(reg, "retiring", in)
		assert.Equal(t, input(), in)
	})

	t.Run("returns settings with nothing to drop as they are", func(t *testing.T) {
		in := map[string]any{"keep": 1, "streaming": map[string]any{"enabled": true}}
		got := appplugins.StripRetiredSettings(reg, "retiring", in)
		require.Equal(t, in, got)
	})

	t.Run("leaves a non-object at a nested path alone", func(t *testing.T) {
		in := map[string]any{"streaming": "on_error"}
		assert.Equal(t, in, appplugins.StripRetiredSettings(reg, "retiring", in))
	})

	t.Run("plugins that declare none, unknown slugs and a nil registry keep every key", func(t *testing.T) {
		assert.Equal(t, input(), appplugins.StripRetiredSettings(reg, "plain", input()))
		assert.Equal(t, input(), appplugins.StripRetiredSettings(reg, "unknown", input()))
		assert.Equal(t, input(), appplugins.StripRetiredSettings(nil, "retiring", input()))
	})
}
