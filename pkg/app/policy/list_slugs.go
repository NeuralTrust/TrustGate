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

package policy

import (
	"sort"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

func ResolveListSlugs(catalog appplugins.Catalog, categories, types []string) (slugs []string, restricted bool) {
	if len(categories) == 0 && len(types) == 0 {
		return nil, false
	}

	typeSet := make(map[string]struct{}, len(types))
	for _, slug := range types {
		if slug == "" {
			continue
		}
		typeSet[slug] = struct{}{}
	}

	if len(categories) == 0 {
		return sortedKeys(typeSet), true
	}

	categorySlugs := make(map[string]struct{})
	wanted := make(map[string]struct{}, len(categories))
	for _, category := range categories {
		if category == "" {
			continue
		}
		wanted[category] = struct{}{}
	}
	for _, group := range catalog.Groups {
		if _, ok := wanted[group.Type]; !ok {
			continue
		}
		for _, item := range group.Items {
			categorySlugs[item.Slug] = struct{}{}
		}
	}

	if len(typeSet) == 0 {
		return sortedKeys(categorySlugs), true
	}

	intersection := make(map[string]struct{})
	for slug := range categorySlugs {
		if _, ok := typeSet[slug]; ok {
			intersection[slug] = struct{}{}
		}
	}
	return sortedKeys(intersection), true
}

func sortedKeys(set map[string]struct{}) []string {
	if len(set) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}
