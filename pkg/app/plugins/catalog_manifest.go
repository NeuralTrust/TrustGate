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
	"sort"
)

// The app console's plugin brand map, config forms and translated strings are
// hand-written per slug, keyed off this catalogue. Nothing used to keep them
// in step: a new guardrail plugin landed here with no brand entry and no
// strings, and read to an operator as an unsupported policy with no icon and
// no copy (RUN-1643, proven by google_model_armor before it was wired up in
// RUN-1642).
//
// CatalogManifest is the machine-readable source the app's CI check compares
// against, so the next plugin that lands here without console support fails a
// build instead of shipping silently.

// CatalogManifestEntry describes one catalog plugin for consumers outside this
// package.
type CatalogManifestEntry struct {
	Slug string `json:"slug"`
	// Group is the product category this plugin is bucketed under in the
	// catalog response (see groupOrder).
	Group string `json:"group"`
	// Guardrail is true when the plugin is grouped under Guardrails, which is
	// what makes it operator-visible policy that needs a brand and strings,
	// not just a generic form.
	Guardrail bool `json:"guardrail"`
}

// CatalogManifest returns every plugin in the catalog metadata, sorted, for
// export.
func CatalogManifest() []CatalogManifestEntry {
	out := make([]CatalogManifestEntry, 0, len(pluginCatalogMeta))
	for slug, meta := range pluginCatalogMeta {
		out = append(out, CatalogManifestEntry{
			Slug:      slug,
			Group:     meta.group,
			Guardrail: meta.group == groupGuardrails,
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out
}

// CatalogManifestJSON is CatalogManifest as indented JSON, which is what the
// exporter writes and the app's CI check reads.
func CatalogManifestJSON() ([]byte, error) {
	data, err := json.MarshalIndent(CatalogManifest(), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
