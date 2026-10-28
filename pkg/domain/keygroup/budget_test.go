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

package keygroup

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

var budgetNow = time.Date(2026, 10, 22, 12, 0, 0, 0, time.UTC)

func usd(v float64) *float64 { return &v }

func TestNewBudget(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	b, err := NewBudget(gw, " g-eng ", usd(100), usd(20), map[string]float64{" alice ": 50, "bob": 0}, " Block ", budgetNow)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	if b.GroupID != "g-eng" || b.Action != ActionBlock || !b.Blocks() || !b.CreatedAt.Equal(budgetNow) {
		t.Fatalf("budget = %+v, want g-eng blocking", b)
	}
	if limit, ok := b.GroupLimit(); !ok || limit != 100 {
		t.Fatalf("group limit = %v, %v", limit, ok)
	}
	for owner, want := range map[string]float64{"alice": 50, "bob": 0, "carol": 20} {
		if limit, ok := b.MemberLimit(owner); !ok || limit != want {
			t.Fatalf("member limit of %s = %v, %v; want %v (an override replaces the default)", owner, limit, ok, want)
		}
	}

	groupOnly, err := NewBudget(gw, "g-sre", usd(10), nil, nil, ActionAlert, budgetNow)
	if err != nil {
		t.Fatalf("group only: %v", err)
	}
	if _, ok := groupOnly.MemberLimit("alice"); ok || groupOnly.Blocks() {
		t.Fatalf("a budget without member limits holds no member, and alert never blocks: %+v", groupOnly)
	}
	overridesOnly, err := NewBudget(gw, "g-ops", nil, nil, map[string]float64{"alice": 5}, ActionAlert, budgetNow)
	if err != nil {
		t.Fatalf("overrides only: %v", err)
	}
	if _, ok := overridesOnly.GroupLimit(); ok {
		t.Fatal("a budget without a group limit holds no group total")
	}
	if _, ok := overridesOnly.MemberLimit("bob"); ok {
		t.Fatal("a member without an override, with no default, is not held")
	}
}

func TestNewBudget_Refused(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	for name, tc := range map[string]struct {
		gateway         ids.GatewayID
		group, action   string
		monthly, member *float64
		overrides       map[string]float64
	}{
		"no gateway":             {group: "g", monthly: usd(1), action: ActionBlock},
		"no group":               {gateway: gw, group: " ", monthly: usd(1), action: ActionBlock},
		"a group id too long":    {gateway: gw, group: strings.Repeat("g", MaxGroupIDLength+1), monthly: usd(1), action: ActionBlock},
		"no limit at all":        {gateway: gw, group: "g", action: ActionBlock},
		"a negative group limit": {gateway: gw, group: "g", monthly: usd(-1), action: ActionBlock},
		"an infinite limit":      {gateway: gw, group: "g", member: usd(math.Inf(1)), action: ActionBlock},
		"a NaN limit":            {gateway: gw, group: "g", member: usd(math.NaN()), action: ActionBlock},
		"a negative override":    {gateway: gw, group: "g", overrides: map[string]float64{"alice": -5}, action: ActionBlock},
		"an override for nobody": {gateway: gw, group: "g", overrides: map[string]float64{" ": 5}, action: ActionBlock},
		"no action":              {gateway: gw, group: "g", monthly: usd(1)},
		"an unknown action":      {gateway: gw, group: "g", monthly: usd(1), action: "throttle"},
	} {
		_, err := NewBudget(tc.gateway, tc.group, tc.monthly, tc.member, tc.overrides, tc.action, budgetNow)
		if !errors.Is(err, ErrInvalidBudget) || !errors.Is(err, commonerrors.ErrValidation) {
			t.Fatalf("%s: err = %v, want ErrInvalidBudget as a validation error", name, err)
		}
	}
	many := make(map[string]float64, MaxMemberOverrides+1)
	for i := range MaxMemberOverrides + 1 {
		many[fmt.Sprintf("member-%d", i)] = 1
	}
	if _, err := NewBudget(gw, "g", nil, nil, many, ActionAlert, budgetNow); !errors.Is(err, ErrInvalidBudget) {
		t.Fatalf("too many overrides: err = %v", err)
	}
}

func TestBudget_CloneSharesNothing(t *testing.T) {
	t.Parallel()
	b, err := NewBudget(ids.New[ids.GatewayKind](), "g", usd(10), usd(2), map[string]float64{"alice": 3}, ActionBlock, budgetNow)
	if err != nil {
		t.Fatalf("NewBudget: %v", err)
	}
	clone := b.Clone()
	*clone.MonthlyLimitUSD, *clone.MemberMonthlyLimitUSD, clone.MemberOverrides["alice"] = 1, 1, 1
	if *b.MonthlyLimitUSD != 10 || *b.MemberMonthlyLimitUSD != 2 || b.MemberOverrides["alice"] != 3 {
		t.Fatalf("a clone changed the budget it was taken from: %+v", b)
	}
	var none *Budget
	if none.Clone() != nil || none.Blocks() {
		t.Fatal("a nil budget clones to nil and blocks nothing")
	}
}
