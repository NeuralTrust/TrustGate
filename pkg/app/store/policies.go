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

package store

import (
	"context"
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// PolicyService is the admin surface over per-principal Store access policies:
// list a gateway's policies and set (or clear) one — the Access page's write
// path for the All / Selected / None switch. Every write signals a snapshot
// rebuild so the data planes pick the level up.
//
//go:generate mockery --name=PolicyService --dir=. --output=./mocks --filename=store_policy_service_mock.go --case=underscore --with-expecter
type PolicyService interface {
	storeaccessdomain.PolicyReader
	// Set replaces the principal's level; an empty Mode clears it so the gateway
	// default applies again.
	Set(ctx context.Context, in SetPolicyRequest) (*storeaccessdomain.Policy, error)
}

// SetPolicyRequest is one policy to write. Mode "" means "inherit the default".
type SetPolicyRequest struct {
	GatewayID     ids.GatewayID
	PrincipalType storeaccessdomain.PrincipalType
	PrincipalID   string
	Mode          string
}

type policyService struct {
	repo     storeaccessdomain.PolicyRepository
	signaler configsyncport.SnapshotSignaler
}

// NewPolicyService wires the policy admin service; signaler may be nil.
func NewPolicyService(repo storeaccessdomain.PolicyRepository, signaler configsyncport.SnapshotSignaler) (PolicyService, error) {
	if repo == nil {
		return nil, ErrUnavailable
	}
	return &policyService{repo: repo, signaler: signaler}, nil
}

func (s *policyService) ListPoliciesByGateway(ctx context.Context, gatewayID ids.GatewayID) ([]*storeaccessdomain.Policy, error) {
	return s.repo.ListPoliciesByGateway(ctx, gatewayID)
}

func (s *policyService) Set(ctx context.Context, in SetPolicyRequest) (*storeaccessdomain.Policy, error) {
	if strings.TrimSpace(in.Mode) == "" {
		if in.GatewayID.IsNil() || strings.TrimSpace(in.PrincipalID) == "" ||
			(in.PrincipalType != storeaccessdomain.PrincipalUser && in.PrincipalType != storeaccessdomain.PrincipalGroup) {
			return nil, fmt.Errorf("store: gateway, principal type and principal id are required: %w", commonerrors.ErrValidation)
		}
		if err := s.repo.DeletePolicy(ctx, in.GatewayID, in.PrincipalType, strings.TrimSpace(in.PrincipalID)); err != nil {
			return nil, err
		}
		s.signal(ctx)
		return nil, nil
	}
	policy, err := storeaccessdomain.NewPolicy(in.GatewayID, in.PrincipalType, in.PrincipalID, in.Mode)
	if err != nil {
		return nil, err
	}
	if err := s.repo.UpsertPolicy(ctx, policy); err != nil {
		return nil, err
	}
	s.signal(ctx)
	return policy, nil
}

func (s *policyService) signal(ctx context.Context) {
	if s.signaler != nil {
		s.signaler.Signal(ctx)
	}
}
