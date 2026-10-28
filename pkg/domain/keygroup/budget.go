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

// Package keygroup holds what a gateway enforces for a directory group whose
// members hold group keys: the group's monthly budget, shared by the group and
// split per member. Which groups exist and who belongs to them is the
// console's; the gateway only keys on the group id a group key carries.
package keygroup

import (
	"fmt"
	"maps"
	"math"
	"strings"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ActionAlert and ActionBlock are what reaching a limit does: record it and
// tell the console, or also refuse the group key's requests until the month
// turns.
const (
	ActionAlert = "alert"
	ActionBlock = "block"
)

// ScopeGroup and ScopeMember name the limit a request met: the group's total,
// or the member's share of it.
const (
	ScopeGroup  = "group"
	ScopeMember = "member"
)

// Bounds that keep a budget row a row. A group id is the console's, a UUID;
// an owner id is a platform user id.
const (
	MaxGroupIDLength   = 256
	MaxOwnerIDLength   = 256
	MaxMemberOverrides = 10000
)

var (
	ErrInvalidBudget = fmt.Errorf("key group budget: invalid budget: %w", commonerrors.ErrValidation)
	ErrNotFound      = fmt.Errorf("key group budget: %w", commonerrors.ErrNotFound)
)

// Budget is the monthly spending limit of one directory group's keys on a
// gateway, in US dollars of priced cost, over the UTC calendar month.
//
// MonthlyLimitUSD caps the group as a whole; MemberMonthlyLimitUSD caps each
// member's own spend through their key for the group; MemberOverrides replaces
// that per-member limit for the members it names. A nil limit is no limit, and
// a request is held to the first limit it has reached. A limit of zero allows
// no spend at all.
type Budget struct {
	GatewayID             ids.GatewayID      `json:"gateway_id"`
	GroupID               string             `json:"group_id"`
	MonthlyLimitUSD       *float64           `json:"monthly_limit_usd,omitempty"`
	MemberMonthlyLimitUSD *float64           `json:"member_monthly_limit_usd,omitempty"`
	MemberOverrides       map[string]float64 `json:"member_overrides,omitempty"`
	Action                string             `json:"action"`
	CreatedAt             time.Time          `json:"created_at"`
	UpdatedAt             time.Time          `json:"updated_at"`
}

// NewBudget builds a validated budget for groupID on gatewayID. The group id,
// the action and the member ids are trimmed; an override for a member named
// twice keeps the last value.
func NewBudget(gatewayID ids.GatewayID, groupID string, monthly, member *float64, overrides map[string]float64, action string, now time.Time) (*Budget, error) {
	b := &Budget{
		GatewayID:             gatewayID,
		GroupID:               strings.TrimSpace(groupID),
		MonthlyLimitUSD:       cloneLimit(monthly),
		MemberMonthlyLimitUSD: cloneLimit(member),
		Action:                strings.ToLower(strings.TrimSpace(action)),
		CreatedAt:             now.UTC(),
		UpdatedAt:             now.UTC(),
	}
	if len(overrides) > 0 {
		b.MemberOverrides = make(map[string]float64, len(overrides))
		for owner, limit := range overrides {
			b.MemberOverrides[strings.TrimSpace(owner)] = limit
		}
	}
	if err := b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

// Validate reports whether b is a budget a group can carry: it names its
// gateway and group, sets at least one limit, every limit is a finite amount
// of dollars no lower than zero, and its action is alert or block.
func (b *Budget) Validate() error {
	if b == nil {
		return fmt.Errorf("%w: nil budget", ErrInvalidBudget)
	}
	if b.GatewayID.IsNil() {
		return fmt.Errorf("%w: gateway id is required", ErrInvalidBudget)
	}
	switch {
	case b.GroupID == "":
		return fmt.Errorf("%w: group_id is required", ErrInvalidBudget)
	case len(b.GroupID) > MaxGroupIDLength:
		return fmt.Errorf("%w: group_id is longer than %d characters", ErrInvalidBudget, MaxGroupIDLength)
	}
	if b.MonthlyLimitUSD == nil && b.MemberMonthlyLimitUSD == nil && len(b.MemberOverrides) == 0 {
		return fmt.Errorf("%w: set monthly_limit_usd, member_monthly_limit_usd or a member override", ErrInvalidBudget)
	}
	if err := validateLimit("monthly_limit_usd", b.MonthlyLimitUSD); err != nil {
		return err
	}
	if err := validateLimit("member_monthly_limit_usd", b.MemberMonthlyLimitUSD); err != nil {
		return err
	}
	if len(b.MemberOverrides) > MaxMemberOverrides {
		return fmt.Errorf("%w: more than %d member overrides", ErrInvalidBudget, MaxMemberOverrides)
	}
	for owner, limit := range b.MemberOverrides {
		switch {
		case owner == "":
			return fmt.Errorf("%w: a member override names no member", ErrInvalidBudget)
		case len(owner) > MaxOwnerIDLength:
			return fmt.Errorf("%w: a member override's member is longer than %d characters", ErrInvalidBudget, MaxOwnerIDLength)
		}
		if err := validateLimit("member_overrides["+owner+"]", &limit); err != nil {
			return err
		}
	}
	switch b.Action {
	case ActionAlert, ActionBlock:
		return nil
	default:
		return fmt.Errorf("%w: action must be %s or %s", ErrInvalidBudget, ActionAlert, ActionBlock)
	}
}

func validateLimit(field string, limit *float64) error {
	if limit == nil {
		return nil
	}
	if math.IsNaN(*limit) || math.IsInf(*limit, 0) || *limit < 0 {
		return fmt.Errorf("%w: %s must be a finite number of dollars, zero or more", ErrInvalidBudget, field)
	}
	return nil
}

// GroupLimit is the group's monthly total, when it has one.
func (b *Budget) GroupLimit() (float64, bool) {
	if b == nil || b.MonthlyLimitUSD == nil {
		return 0, false
	}
	return *b.MonthlyLimitUSD, true
}

// MemberLimit is what ownerID may spend in a month through their key for the
// group: their override when they have one, else the per-member limit.
func (b *Budget) MemberLimit(ownerID string) (float64, bool) {
	if b == nil {
		return 0, false
	}
	if limit, ok := b.MemberOverrides[ownerID]; ok {
		return limit, true
	}
	if b.MemberMonthlyLimitUSD == nil {
		return 0, false
	}
	return *b.MemberMonthlyLimitUSD, true
}

// Blocks reports whether reaching a limit refuses requests rather than only
// recording it.
func (b *Budget) Blocks() bool {
	return b != nil && b.Action == ActionBlock
}

// Clone returns a deep copy of b, nil for nil, so a request never shares the
// budget a cache or a snapshot holds.
func (b *Budget) Clone() *Budget {
	if b == nil {
		return nil
	}
	out := *b
	out.MonthlyLimitUSD = cloneLimit(b.MonthlyLimitUSD)
	out.MemberMonthlyLimitUSD = cloneLimit(b.MemberMonthlyLimitUSD)
	out.MemberOverrides = maps.Clone(b.MemberOverrides)
	return &out
}

func cloneLimit(limit *float64) *float64 {
	if limit == nil {
		return nil
	}
	v := *limit
	return &v
}
