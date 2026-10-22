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

// Package request holds the bodies of the key group budget routes.
package request

// SetBudgetRequest is a directory group's monthly budget on a gateway, in US
// dollars. A null or absent limit is no limit; at least one limit or override
// is required.
type SetBudgetRequest struct {
	// MonthlyLimitUSD is the group's total for the month, shared by every
	// member.
	MonthlyLimitUSD *float64 `json:"monthly_limit_usd" example:"500"`
	// MemberMonthlyLimitUSD is what each member may spend in the month through
	// their key for the group.
	MemberMonthlyLimitUSD *float64 `json:"member_monthly_limit_usd" example:"50"`
	// MemberOverrides replaces MemberMonthlyLimitUSD for the members it names,
	// by platform user id.
	MemberOverrides map[string]float64 `json:"member_overrides,omitempty"`
	// Action is what reaching a limit does: alert records it and tells the
	// console; block also refuses the group's keys until the month turns.
	Action string `json:"action" enums:"alert,block" example:"block"`
}
