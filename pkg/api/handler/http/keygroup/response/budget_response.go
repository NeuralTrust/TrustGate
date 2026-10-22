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

// Package response holds the bodies the key group budget routes answer with.
package response

import (
	"maps"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
)

// BudgetResponse is a directory group's monthly budget on a gateway. A null
// limit is no limit.
type BudgetResponse struct {
	GroupID               string             `json:"group_id" example:"0199a000-0000-7000-8000-00000000000a"`
	MonthlyLimitUSD       *float64           `json:"monthly_limit_usd" example:"500"`
	MemberMonthlyLimitUSD *float64           `json:"member_monthly_limit_usd" example:"50"`
	MemberOverrides       map[string]float64 `json:"member_overrides"`
	Action                string             `json:"action" enums:"alert,block" example:"block"`
	CreatedAt             time.Time          `json:"created_at"`
	UpdatedAt             time.Time          `json:"updated_at"`
}

// BudgetListResponse is every group budget of a gateway.
type BudgetListResponse struct {
	Items []BudgetResponse `json:"items"`
}

// FromBudget maps a budget, its overrides an empty object rather than null.
func FromBudget(b *domain.Budget) BudgetResponse {
	overrides := maps.Clone(b.MemberOverrides)
	if overrides == nil {
		overrides = map[string]float64{}
	}
	return BudgetResponse{
		GroupID:               b.GroupID,
		MonthlyLimitUSD:       b.MonthlyLimitUSD,
		MemberMonthlyLimitUSD: b.MemberMonthlyLimitUSD,
		MemberOverrides:       overrides,
		Action:                b.Action,
		CreatedAt:             b.CreatedAt,
		UpdatedAt:             b.UpdatedAt,
	}
}

// FromBudgets maps a gateway's budgets, an empty list rather than null.
func FromBudgets(budgets []*domain.Budget) BudgetListResponse {
	out := BudgetListResponse{Items: make([]BudgetResponse, 0, len(budgets))}
	for _, b := range budgets {
		out.Items = append(out.Items, FromBudget(b))
	}
	return out
}
