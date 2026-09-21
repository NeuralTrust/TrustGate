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
	"encoding/json"
	"testing"
)

// TestCatalogManifestCoversEveryPlugin is the guarantee the app's CI check
// depends on. If the manifest could omit a plugin, the check would pass while
// the console was missing a brand or strings for it.
func TestCatalogManifestCoversEveryPlugin(t *testing.T) {
	m := CatalogManifest()
	if len(m) != len(pluginCatalogMeta) {
		t.Fatalf("manifest has %d entries, catalog metadata has %d", len(m), len(pluginCatalogMeta))
	}
	seen := make(map[string]bool, len(m))
	for _, e := range m {
		if _, ok := pluginCatalogMeta[e.Slug]; !ok {
			t.Errorf("manifest lists %q, which is not in pluginCatalogMeta", e.Slug)
		}
		if seen[e.Slug] {
			t.Errorf("manifest lists %q twice", e.Slug)
		}
		seen[e.Slug] = true
	}
	for slug := range pluginCatalogMeta {
		if !seen[slug] {
			t.Errorf("manifest omits %s", slug)
		}
	}
}

// TestCatalogManifestFlagsMatchTheCatalogue pins the fields the app's drift
// guard relies on: group and the guardrail derivation from it.
func TestCatalogManifestFlagsMatchTheCatalogue(t *testing.T) {
	for _, e := range CatalogManifest() {
		meta := pluginCatalogMeta[e.Slug]
		if e.Group != meta.group {
			t.Errorf("%s group = %q, want %q", e.Slug, e.Group, meta.group)
		}
		wantGuardrail := meta.group == groupGuardrails
		if e.Guardrail != wantGuardrail {
			t.Errorf("%s guardrail = %v, want %v", e.Slug, e.Guardrail, wantGuardrail)
		}
	}
}

func TestCatalogManifestJSONIsStable(t *testing.T) {
	first, err := CatalogManifestJSON()
	if err != nil {
		t.Fatalf("CatalogManifestJSON: %v", err)
	}
	second, err := CatalogManifestJSON()
	if err != nil {
		t.Fatalf("CatalogManifestJSON: %v", err)
	}
	if string(first) != string(second) {
		t.Error("CatalogManifestJSON is not deterministic; the app's CI diff would flap")
	}
	var parsed []CatalogManifestEntry
	if err := json.Unmarshal(first, &parsed); err != nil {
		t.Fatalf("manifest is not valid JSON: %v", err)
	}
	if len(parsed) != len(pluginCatalogMeta) {
		t.Errorf("round-trip lost entries: %d vs %d", len(parsed), len(pluginCatalogMeta))
	}
}

// TestCatalogManifestIncludesGoogleModelArmor pins the plugin RUN-1643's guard
// was built to catch: it must be reported as a guardrail so app's drift check
// can compare it against the console's brand map and strings.
func TestCatalogManifestIncludesGoogleModelArmor(t *testing.T) {
	for _, e := range CatalogManifest() {
		if e.Slug == "google_model_armor" {
			if !e.Guardrail {
				t.Errorf("google_model_armor guardrail = false, want true")
			}
			return
		}
	}
	t.Fatal("manifest omits google_model_armor")
}
