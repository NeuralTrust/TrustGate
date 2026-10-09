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

package catalog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLiveModelsTTL(t *testing.T) {
	t.Parallel()

	assert.Equal(t, liveModelsTransientTTL, liveModelsTTL(nil), "an empty listing may only mean nothing is deployed yet")
	assert.Equal(t, liveModelsTransientTTL, liveModelsTTL([]LiveModel{{ID: "a"}, {ID: "b", Pending: true}}),
		"a deployment being created must show up once it serves")
	assert.Equal(t, liveModelsCacheTTL, liveModelsTTL([]LiveModel{{ID: "a"}}))
}
