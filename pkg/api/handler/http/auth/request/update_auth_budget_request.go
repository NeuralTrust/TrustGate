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

package request

import (
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
)

// UpdateAuthBudgetRequest is the spending limit of a personal key. A JSON null
// in its place clears the budget.
type UpdateAuthBudgetRequest struct {
	Max        float64 `json:"max" example:"50"`
	Unit       string  `json:"unit" enums:"tokens,dollars" example:"dollars"`
	TimeWindow string  `json:"time_window" enums:"calendar_month,calendar_day" example:"calendar_month"`
}

// ToBudget returns the budget the body asks for, nil for a null body, leaving
// its validation to the domain.
func (r *UpdateAuthBudgetRequest) ToBudget() *domain.KeyBudget {
	if r == nil {
		return nil
	}
	return &domain.KeyBudget{Max: r.Max, Unit: r.Unit, TimeWindow: r.TimeWindow}
}
