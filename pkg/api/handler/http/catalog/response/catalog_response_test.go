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

package response

import (
	"encoding/json"
	"strings"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

func TestFromModel_CapabilitiesField(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(FromModel(domain.Model{
		Slug:         "text-embedding-3-small",
		Capabilities: map[string]any{"embed": true},
		Enabled:      true,
		Source:       "models.dev",
	}))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var body map[string]any
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	caps, ok := body["capabilities"].(map[string]any)
	if !ok {
		t.Fatalf("capabilities = %#v, want an object", body["capabilities"])
	}
	if caps["embed"] != true {
		t.Fatalf("capabilities = %#v, want embed true", caps)
	}

	unknown, err := json.Marshal(FromModel(domain.Model{Slug: "mystery", Enabled: true, Source: "models.dev"}))
	if err != nil {
		t.Fatalf("marshal unknown: %v", err)
	}
	if strings.Contains(string(unknown), "capabilities") {
		t.Fatalf("unknown capabilities must be omitted, got %s", unknown)
	}
}
