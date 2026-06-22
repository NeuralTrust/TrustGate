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

func TestCost_MarshalJSON_UsesDecimalNotation(t *testing.T) {
	cost := events.Cost{
		PromptUsd:     events.DecimalFloat(2.4e-6),
		CompletionUsd: events.DecimalFloat(1.44e-5),
		TotalUsd:      events.DecimalFloat(1.68e-5),
		Currency:      "USD",
	}

	data, err := json.Marshal(cost)
	require.NoError(t, err)

	s := string(data)
	scientific := regexp.MustCompile(`[0-9]e[+-]?[0-9]`)
	assert.False(t, scientific.MatchString(s), "cost JSON must not use scientific notation: %s", s)
	assert.JSONEq(t, `{
		"prompt_usd": 0.0000024,
		"completion_usd": 0.0000144,
		"total_usd": 0.0000168,
		"currency": "USD"
	}`, s)
}
