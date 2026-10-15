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

package openaimoderation

import "sort"

// Known models, confirmed against a live /v1/moderations call on 2026-09-28:
// both return all 13 categories in every result, image-only input included.
// text-moderation-latest and text-moderation-stable now answer 400 "Invalid
// value for 'model'", so they are left out and treated as unknown.
const (
	ModelOmniLatest   = "omni-moderation-latest"
	ModelOmni20240926 = "omni-moderation-2024-09-26"
)

const (
	CategoryHarassment            = "harassment"
	CategoryHarassmentThreatening = "harassment/threatening"
	CategoryHate                  = "hate"
	CategoryHateThreatening       = "hate/threatening"
	CategoryIllicit               = "illicit"
	CategoryIllicitViolent        = "illicit/violent"
	CategorySelfHarm              = "self-harm"
	CategorySelfHarmIntent        = "self-harm/intent"
	CategorySelfHarmInstructions  = "self-harm/instructions"
	CategorySexual                = "sexual"
	CategorySexualMinors          = "sexual/minors"
	CategoryViolence              = "violence"
	CategoryViolenceGraphic       = "violence/graphic"
)

var omniCategories = []string{
	CategoryHarassment, CategoryHarassmentThreatening,
	CategoryHate, CategoryHateThreatening,
	CategoryIllicit, CategoryIllicitViolent,
	CategorySelfHarm, CategorySelfHarmIntent, CategorySelfHarmInstructions,
	CategorySexual, CategorySexualMinors,
	CategoryViolence, CategoryViolenceGraphic,
}

var modelCategorySets = buildModelCategorySets()

func buildModelCategorySets() map[string]map[string]struct{} {
	omni := toSet(omniCategories)
	return map[string]map[string]struct{}{
		ModelOmniLatest:   omni,
		ModelOmni20240926: omni,
	}
}

func toSet(values []string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, v := range values {
		set[v] = struct{}{}
	}
	return set
}

// categoriesForModel returns the known category set for model and whether
// model itself is recognised. An unknown model reports ok=false and a nil
// set: there is nothing to check keys against.
func categoriesForModel(model string) (set map[string]struct{}, ok bool) {
	set, ok = modelCategorySets[model]
	return set, ok
}

func isKnownModel(model string) bool {
	_, ok := modelCategorySets[model]
	return ok
}

// sortedCategoryNames lists model's known categories in deterministic order,
// for error messages. An unknown model returns nil.
func sortedCategoryNames(model string) []string {
	set, ok := categoriesForModel(model)
	if !ok {
		return nil
	}
	names := make([]string, 0, len(set))
	for c := range set {
		names = append(names, c)
	}
	sort.Strings(names)
	return names
}

// knownModelNames lists every model this build recognises, sorted.
func knownModelNames() []string {
	names := make([]string, 0, len(modelCategorySets))
	for m := range modelCategorySets {
		names = append(names, m)
	}
	sort.Strings(names)
	return names
}
