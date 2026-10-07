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
	"encoding/json"
	"errors"
	"math"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func TestKeyBudget_Validate(t *testing.T) {
	t.Parallel()
	for name, tc := range map[string]struct {
		budget KeyBudget
		valid  bool
	}{
		"monthly dollars":      {budget: KeyBudget{Max: 50, Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarMonth}, valid: true},
		"daily fraction":       {budget: KeyBudget{Max: 0.25, Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarDay}, valid: true},
		"zero":                 {budget: KeyBudget{Max: 0, Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarMonth}},
		"negative":             {budget: KeyBudget{Max: -1, Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarMonth}},
		"not a number":         {budget: KeyBudget{Max: math.NaN(), Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarMonth}},
		"infinite":             {budget: KeyBudget{Max: math.Inf(1), Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarMonth}},
		"rolling window":       {budget: KeyBudget{Max: 50, Unit: BudgetUnitDollars, TimeWindow: "24h"}},
		"no window":            {budget: KeyBudget{Max: 50, Unit: BudgetUnitDollars}},
		"no unit":              {budget: KeyBudget{Max: 50, TimeWindow: BudgetWindowCalendarMonth}},
		"unknown unit":         {budget: KeyBudget{Max: 50, Unit: "euros", TimeWindow: BudgetWindowCalendarMonth}},
		"whole tokens":         {budget: KeyBudget{Max: 100000, Unit: BudgetUnitTokens, TimeWindow: BudgetWindowCalendarDay}, valid: true},
		"fractional tokens":    {budget: KeyBudget{Max: 0.5, Unit: BudgetUnitTokens, TimeWindow: BudgetWindowCalendarDay}},
		"window not canonical": {budget: KeyBudget{Max: 50, Unit: BudgetUnitDollars, TimeWindow: "Calendar_Month"}},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.budget.Validate()
			if tc.valid && err != nil || !tc.valid && !errors.Is(err, ErrInvalidBudget) {
				t.Fatalf("Validate(%+v) = %v, want valid %v", tc.budget, err, tc.valid)
			}
		})
	}
	if !errors.Is(ErrInvalidBudget, commonerrors.ErrValidation) {
		t.Fatal("ErrInvalidBudget must answer as a validation error")
	}
}

func TestAuth_SetBudget(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.FixedZone("CEST", 7200))
	budget := &KeyBudget{Max: 50, Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarMonth}

	owned := &Auth{OwnerID: "alice"}
	if err := owned.SetBudget(budget, now); err != nil {
		t.Fatalf("SetBudget on an owned key: %v", err)
	}
	if owned.Budget == budget || *owned.Budget != *budget || !owned.UpdatedAt.Equal(now) || owned.UpdatedAt.Location() != time.UTC {
		t.Fatalf("auth = %+v, want a copy of %+v stamped at %v in UTC", owned, budget, now)
	}
	budget.Max = 1
	if owned.Budget.Max != 50 {
		t.Fatal("the auth must not share the caller's budget")
	}
	if err := owned.SetBudget(&KeyBudget{Max: 50, Unit: BudgetUnitDollars, TimeWindow: "1h"}, now); !errors.Is(err, ErrInvalidBudget) || owned.Budget.Max != 50 {
		t.Fatalf("an invalid budget: err = %v, budget = %+v, want ErrInvalidBudget and the budget kept", err, owned.Budget)
	}
	if err := owned.SetBudget(nil, now); err != nil || owned.Budget != nil {
		t.Fatalf("clearing: err = %v, budget = %+v", err, owned.Budget)
	}

	application := &Auth{}
	for _, b := range []*KeyBudget{{Max: 50, Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarMonth}, nil} {
		if err := application.SetBudget(b, now); !errors.Is(err, ErrApplicationKey) || !application.UpdatedAt.IsZero() {
			t.Fatalf("SetBudget(%+v) on an application key = %v, want ErrApplicationKey and no change", b, err)
		}
	}
	if errors.Is(ErrApplicationKey, commonerrors.ErrValidation) {
		t.Fatal("ErrApplicationKey must answer with its own code, not as a validation error")
	}
}

func TestKeyBudget_Clone(t *testing.T) {
	t.Parallel()
	if (*KeyBudget)(nil).Clone() != nil {
		t.Fatal("Clone of nil must be nil")
	}
	b := &KeyBudget{Max: 5, Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarDay}
	if c := b.Clone(); c == b || *c != *b {
		t.Fatalf("Clone() = %p %+v, want a distinct copy of %p %+v", c, c, b, b)
	}
}

func TestAuth_BudgetJSON(t *testing.T) {
	t.Parallel()
	raw, err := json.Marshal(&Auth{OwnerID: "alice", Budget: &KeyBudget{Max: 50, Unit: BudgetUnitDollars, TimeWindow: BudgetWindowCalendarMonth}})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if want := map[string]any{"max": float64(50), "unit": "dollars", "time_window": "calendar_month"}; !jsonEqual(got["budget"], want) {
		t.Fatalf("budget = %v, want %v", got["budget"], want)
	}
	raw, err = json.Marshal(&Auth{})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var unbudgeted map[string]any
	if err := json.Unmarshal(raw, &unbudgeted); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := unbudgeted["budget"]; ok {
		t.Fatalf("an auth without a budget must not carry the field: %s", raw)
	}
}

func jsonEqual(a, b any) bool {
	ra, errA := json.Marshal(a)
	rb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ra) == string(rb)
}
