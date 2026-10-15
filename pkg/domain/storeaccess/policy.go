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

package storeaccess

import (
	"context"
	"fmt"
	"strings"
	"time"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// PrincipalType says what a policy's PrincipalID names.
type PrincipalType string

const (
	// PrincipalUser: PrincipalID is the principal subject (the token's sub).
	PrincipalUser PrincipalType = "user"
	// PrincipalGroup: PrincipalID is a group key, matched against the token's
	// groups claim exactly like a grant's Groups entry.
	PrincipalGroup PrincipalType = "group"
)

// Policy is a principal's Store access level on one gateway — "open" (All),
// "curated" (Selected) or "none" — set by an admin on the Access page and
// evaluated live by the gateway on every request, so a change applies at once
// rather than on the principal's next login. Absent policy = the gateway's
// default mode. Precedence: the user's own policy, then the most permissive of
// the policies on the groups the token carries, then the gateway default.
type Policy struct {
	GatewayID     ids.GatewayID
	PrincipalType PrincipalType
	PrincipalID   string
	Mode          string
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// NewPolicy builds a validated policy.
func NewPolicy(gatewayID ids.GatewayID, principalType PrincipalType, principalID, mode string) (*Policy, error) {
	p := &Policy{
		GatewayID:     gatewayID,
		PrincipalType: principalType,
		PrincipalID:   strings.TrimSpace(principalID),
		Mode:          strings.ToLower(strings.TrimSpace(mode)),
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	p.CreatedAt, p.UpdatedAt = now, now
	return p, nil
}

// Validate checks the policy's identity and mode.
func (p *Policy) Validate() error {
	if p == nil {
		return fmt.Errorf("%w: nil policy", ErrInvalidPolicy)
	}
	if p.GatewayID.IsNil() {
		return fmt.Errorf("%w: gateway id is required", ErrInvalidPolicy)
	}
	if p.PrincipalType != PrincipalUser && p.PrincipalType != PrincipalGroup {
		return fmt.Errorf("%w: principal type must be user or group", ErrInvalidPolicy)
	}
	if strings.TrimSpace(p.PrincipalID) == "" {
		return fmt.Errorf("%w: principal id is required", ErrInvalidPolicy)
	}
	if !ValidMode(p.Mode) {
		return fmt.Errorf("%w: mode must be open, curated or none", ErrInvalidPolicy)
	}
	return nil
}

// ValidMode reports whether mode is one of the three Store modes.
func ValidMode(mode string) bool {
	switch mode {
	case gatewaydomain.StoreModeOpen, gatewaydomain.StoreModeCurated, gatewaydomain.StoreModeNone:
		return true
	default:
		return false
	}
}

// PolicyReader is the read side every plane has: the policies of one gateway.
type PolicyReader interface {
	ListPoliciesByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*Policy, error)
}

// PolicyRepository is the control-plane store, keyed by
// (gateway, principal type, principal id).
//
//go:generate mockery --name=PolicyRepository --dir=. --output=./mocks --filename=store_policy_repository_mock.go --case=underscore --with-expecter
type PolicyRepository interface {
	PolicyReader
	// ListPolicies pages every policy across gateways (snapshot compiler).
	ListPolicies(ctx context.Context, page, size int) ([]*Policy, int, error)
	// UpsertPolicy creates or replaces the principal's policy on the gateway.
	UpsertPolicy(ctx context.Context, p *Policy) error
	// DeletePolicy removes the principal's policy (back to the gateway default);
	// missing is not an error.
	DeletePolicy(ctx context.Context, gatewayID ids.GatewayID, principalType PrincipalType, principalID string) error
}

// PolicySet indexes one gateway's policies for the live mode decision.
type PolicySet struct {
	users  map[string]string
	groups map[string]string
}

// IndexPolicies builds a PolicySet; invalid modes are skipped.
func IndexPolicies(policies []*Policy) *PolicySet {
	s := &PolicySet{users: map[string]string{}, groups: map[string]string{}}
	for _, p := range policies {
		if p == nil || !ValidMode(p.Mode) {
			continue
		}
		switch p.PrincipalType {
		case PrincipalUser:
			s.users[p.PrincipalID] = p.Mode
		case PrincipalGroup:
			s.groups[p.PrincipalID] = p.Mode
		}
	}
	return s
}

// Mode resolves the principal's level: their own policy, else the most
// permissive policy among their groups, else "" (no policy applies).
func (s *PolicySet) Mode(subject string, groups []string) string {
	if s == nil {
		return ""
	}
	if sub := strings.TrimSpace(subject); sub != "" {
		if m, ok := s.users[sub]; ok {
			return m
		}
	}
	best := ""
	for _, g := range groups {
		m, ok := s.groups[strings.TrimSpace(g)]
		if !ok {
			continue
		}
		if best == "" || modeRank(m) > modeRank(best) {
			best = m
		}
	}
	return best
}

func modeRank(mode string) int {
	switch mode {
	case gatewaydomain.StoreModeOpen:
		return 2
	case gatewaydomain.StoreModeCurated:
		return 1
	default:
		return 0
	}
}
