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

package tokenratelimit

import (
	"encoding/json"
	"net/http"
	"strconv"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

const (
	tokenBudgetExceeded  = "token_budget_exceeded" // #nosec G101
	dollarBudgetExceeded = "dollar_budget_exceeded"

	headerBudgetUnit         = "X-Budget-Unit"
	headerBudgetScope        = "X-Budget-Scope"
	headerBudgetWindow       = "X-Budget-Window"
	headerBudgetLimitUSD     = "X-Budget-Limit-Usd"
	headerBudgetRemainingUSD = "X-Budget-Remaining-Usd"
	headerBudgetReset        = "X-Budget-Reset"
)

func dollarBudgetHeaders(limitMicros, consumedMicros int64, scope, window string, resetSeconds int) map[string][]string {
	remaining := limitMicros - consumedMicros
	if remaining < 0 {
		remaining = 0
	}
	return map[string][]string{
		headerBudgetUnit:         {unitDollars},
		headerBudgetScope:        {scope},
		headerBudgetWindow:       {window},
		headerBudgetLimitUSD:     {formatUSD(limitMicros)},
		headerBudgetRemainingUSD: {formatUSD(remaining)},
		headerBudgetReset:        {strconv.Itoa(resetSeconds) + "s"},
	}
}

func formatUSD(micros int64) string {
	return strconv.FormatFloat(float64(micros)/1e6, 'f', 6, 64)
}

func withBudgetMeta(headers map[string][]string, unit, scope, window string) map[string][]string {
	if headers == nil {
		headers = map[string][]string{}
	}
	if _, ok := headers[headerBudgetUnit]; !ok {
		headers[headerBudgetUnit] = []string{unit}
	}
	if _, ok := headers[headerBudgetScope]; !ok {
		headers[headerBudgetScope] = []string{scope}
	}
	if _, ok := headers[headerBudgetWindow]; !ok {
		headers[headerBudgetWindow] = []string{window}
	}
	return headers
}

func budgetExceededError(unit, scope, window string, headers map[string][]string) *appplugins.PluginError {
	errType := tokenBudgetExceeded
	if unit == unitDollars {
		errType = dollarBudgetExceeded
	}
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"type":   errType,
			"scope":  scope,
			"window": window,
		},
	})
	return &appplugins.PluginError{
		StatusCode: http.StatusTooManyRequests,
		Message:    errType,
		Headers:    headers,
		Body:       body,
	}
}
