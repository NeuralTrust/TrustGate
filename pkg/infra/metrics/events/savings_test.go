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

package events_test

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSavings_MarshalJSON_UsesDecimalNotation(t *testing.T) {
	savings := events.Savings{
		BaselineModel:         "gpt-5",
		BaselineRegistryID:    "reg-1",
		BaselinePromptUsd:     events.DecimalFloat(2.4e-7),
		BaselineCompletionUsd: events.DecimalFloat(1.44e-6),
		BaselineTotalUsd:      events.DecimalFloat(1.68e-6),
		SavedUsd:              events.DecimalFloat(1.512e-6),
		Currency:              "USD",
	}

	data, err := json.Marshal(savings)
	require.NoError(t, err)

	s := string(data)
	scientific := regexp.MustCompile(`[0-9]e[+-]?[0-9]`)
	assert.False(t, scientific.MatchString(s), "savings JSON must not use scientific notation: %s", s)
	assert.JSONEq(t, `{
		"baseline_model": "gpt-5",
		"baseline_registry_id": "reg-1",
		"baseline_prompt_usd": 0.00000024,
		"baseline_completion_usd": 0.00000144,
		"baseline_total_usd": 0.00000168,
		"saved_usd": 0.000001512,
		"currency": "USD"
	}`, s)
}

// A request served by the top tier saves nothing, and that zero has to survive
// serialization: omitempty on the amount would make "no savings" and "savings
// not computed" indistinguishable downstream.
func TestSavings_MarshalJSON_KeepsZeroSaved(t *testing.T) {
	data, err := json.Marshal(events.Savings{BaselineModel: "gpt-5", Currency: "USD"})
	require.NoError(t, err)

	assert.JSONEq(t, `{
		"baseline_model": "gpt-5",
		"baseline_prompt_usd": 0,
		"baseline_completion_usd": 0,
		"baseline_total_usd": 0,
		"saved_usd": 0,
		"currency": "USD"
	}`, string(data))
}
