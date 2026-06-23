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

package migrations

import (
	"strings"
	"testing"
)

func TestCleanupCrossGatewayConsumerRegistryDeletesOnlyCrossGatewayRows(t *testing.T) {
	t.Parallel()

	required := []string{
		"DELETE FROM consumer_registry",
		"USING consumers c, registries r",
		"cr.consumer_id = c.id",
		"cr.registry_id = r.id",
		"c.gateway_id <> r.gateway_id",
	}
	for _, frag := range required {
		if !strings.Contains(cleanupCrossGatewayConsumerRegistryDDL, frag) {
			t.Fatalf("cleanup DDL missing required fragment %q", frag)
		}
	}
}
