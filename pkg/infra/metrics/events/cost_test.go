package events_test

import (
	"encoding/json"
	"regexp"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/infra/metrics/events"
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
