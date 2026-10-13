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

package plugins

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
)

// The console seeds a new policy's description from its catalogue entry, and
// the Admin API rejects a description above policy.MaxDescriptionLen, so a
// longer catalogue description makes the policy impossible to create.
func TestPluginCatalogMeta_DescriptionsFitPolicyDescriptionLimit(t *testing.T) {
	for slug, meta := range pluginCatalogMeta {
		assert.LessOrEqualf(t, len(meta.description), policy.MaxDescriptionLen,
			"catalogue description of %q is %d bytes, above the policy description limit", slug, len(meta.description))
	}
}
