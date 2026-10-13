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

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// The stream leg runs under the plugin's default guard timeout whatever a stored
// policy says, so the key is dropped on write and by the migration, while the
// fail-closed streaming.on_error a rewriter honours stays.
func TestRetiredSettingsCoverTheIgnoredGuardTimeout(t *testing.T) {
	t.Parallel()
	retired := New(adapter.NewRegistry(), nil).RetiredSettings()
	assert.Contains(t, retired, "streaming.guard_timeout")
	assert.Contains(t, retired, "on_mask_failure")
	assert.NotContains(t, retired, "streaming.on_error")
}
