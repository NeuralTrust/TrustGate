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

func SlugCandidates(models ...string) []string {
	var slugs []string
	for _, model := range models {
		slugs = appendModelSlugs(slugs, model)
	}
	return uniqueNonEmptySlugs(slugs...)
}

func appendModelSlugs(dst []string, model string) []string {
	if model == "" {
		return dst
	}
	dst = append(dst, model)
	if base := DeploymentCatalogSlug(model); base != model {
		dst = append(dst, base)
	}
	return dst
}

func DeploymentCatalogSlug(model string) string {
	const dateSuffixLen = 10
	if len(model) <= dateSuffixLen+1 {
		return model
	}
	suffix := model[len(model)-dateSuffixLen:]
	if suffix[4] != '-' || suffix[7] != '-' {
		return model
	}
	for _, ch := range suffix {
		if ch != '-' && (ch < '0' || ch > '9') {
			return model
		}
	}
	return model[:len(model)-dateSuffixLen-1]
}

func uniqueNonEmptySlugs(slugs ...string) []string {
	seen := make(map[string]struct{}, len(slugs))
	out := make([]string, 0, len(slugs))
	for _, slug := range slugs {
		if slug == "" {
			continue
		}
		if _, dup := seen[slug]; dup {
			continue
		}
		seen[slug] = struct{}{}
		out = append(out, slug)
	}
	return out
}
