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

package auth

import (
	"fmt"
	"math"
	"time"
)

// BudgetWindowCalendarMonth and BudgetWindowCalendarDay are the windows a key
// budget resets on, at the start of each UTC month or day. token_rate_limiter
// shares the names for its own calendar windows.
const (
	BudgetWindowCalendarMonth = "calendar_month"
	BudgetWindowCalendarDay   = "calendar_day"
)

// BudgetUnitTokens and BudgetUnitDollars are the units a key budget is
// counted in. token_rate_limiter shares the names for its own unit.
const (
	BudgetUnitTokens  = "tokens"
	BudgetUnitDollars = "dollars"
)

// KeyBudget is the spending limit of one personal key. It replaces the
// aggregate of every token_rate_limiter policy with key_budgets that counts in
// the same Unit; a policy counting in the other unit keeps its own limit.
type KeyBudget struct {
	Max        float64 `json:"max"`
	Unit       string  `json:"unit"`
	TimeWindow string  `json:"time_window"`
}

// Validate reports whether b is a budget a key can carry.
func (b KeyBudget) Validate() error {
	if math.IsNaN(b.Max) || math.IsInf(b.Max, 0) || b.Max <= 0 {
		return fmt.Errorf("%w: max must be a finite number above zero", ErrInvalidBudget)
	}
	switch b.Unit {
	case BudgetUnitDollars:
	case BudgetUnitTokens:
		if b.Max != math.Trunc(b.Max) {
			return fmt.Errorf("%w: max must be a whole number of tokens", ErrInvalidBudget)
		}
	default:
		return fmt.Errorf("%w: unit must be %s or %s", ErrInvalidBudget, BudgetUnitTokens, BudgetUnitDollars)
	}
	switch b.TimeWindow {
	case BudgetWindowCalendarMonth, BudgetWindowCalendarDay:
		return nil
	default:
		return fmt.Errorf("%w: time_window must be %s or %s", ErrInvalidBudget, BudgetWindowCalendarMonth, BudgetWindowCalendarDay)
	}
}

// Clone returns a copy of b, nil for nil, so a request never shares the budget
// of a cached auth.
func (b *KeyBudget) Clone() *KeyBudget {
	if b == nil {
		return nil
	}
	clone := *b
	return &clone
}

// SetBudget replaces the budget of an owned key, or clears it when b is nil.
// An application key has no owner to hold to a budget and is refused.
func (a *Auth) SetBudget(b *KeyBudget, now time.Time) error {
	if !a.IsOwned() {
		return ErrApplicationKey
	}
	if b != nil {
		if err := b.Validate(); err != nil {
			return err
		}
	}
	a.Budget = b.Clone()
	a.UpdatedAt = now.UTC()
	return nil
}
