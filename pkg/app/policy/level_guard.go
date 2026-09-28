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

package policy

import (
	"context"
	"errors"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// LevelLock serializes the writes that place a plugin somewhere in a gateway.
// It takes the lock of one (gateway, slug), reads the enabled policies of that
// pair other than exclude, and holds the lock until fn returns, so the check
// and the write it authorises decide on the same state.
//
// exclude is the policy being written: an update and a promotion rewrite their
// own row, and a lock held on it would be a lock the write then waits for.
//
//go:generate mockery --name=LevelLock --dir=. --output=./mocks --filename=policy_level_lock_mock.go --case=underscore --with-expecter
type LevelLock interface {
	WithSlugLocked(
		ctx context.Context,
		gatewayID ids.GatewayID,
		slug string,
		exclude ids.PolicyID,
		fn func(ctx context.Context, occupants []*domain.Policy) error,
	) error
}

// LevelGuard refuses the writes that would put a second policy of the same
// plugin on a level the gateway already runs that plugin at (RUN-1621, rule
// 3). Every write path that can take a level goes through it: create, update
// — including the one that only turns enabled on, or the rule would be
// sidestepped by saving disabled and switching on afterwards — attach and
// promotion. Detaching and demoting only release levels.
//
//go:generate mockery --name=LevelGuard --dir=. --output=./mocks --filename=policy_level_guard_mock.go --case=underscore --with-expecter
type LevelGuard interface {
	// Check runs write when the levels p would take are free, and returns
	// ErrPolicyLevelConflict naming the policy that holds one of them
	// otherwise. p is the policy as it would be stored, so a caller that is
	// about to attach a consumer or promote to global passes a copy carrying
	// that change.
	Check(ctx context.Context, p *domain.Policy, write func(ctx context.Context) error) error
}

var _ LevelGuard = (*levelGuard)(nil)

type levelGuard struct {
	lock LevelLock
}

// NewLevelGuard builds the guard over the lock the policy store provides.
func NewLevelGuard(lock LevelLock) LevelGuard {
	return &levelGuard{lock: lock}
}

func (g *levelGuard) Check(ctx context.Context, p *domain.Policy, write func(ctx context.Context) error) error {
	if p == nil || write == nil {
		return errors.New("policy: level guard: nil policy or write")
	}
	taken := p.Occupancy()
	if taken.Len() == 0 {
		return write(ctx)
	}
	return g.lock.WithSlugLocked(ctx, p.GatewayID, p.Slug, p.ID, func(ctx context.Context, occupants []*domain.Policy) error {
		if err := firstConflict(taken, p.ID, occupants); err != nil {
			return err
		}
		return write(ctx)
	})
}

// firstConflict names the occupant that shares a level with taken. It compares
// sets rather than rows: two policies clash as soon as their occupancies
// intersect, which is what catches the frequent case of a registry added to
// one of two policies that already list others.
func firstConflict(taken domain.OccupancySet, id ids.PolicyID, occupants []*domain.Policy) error {
	for _, q := range occupants {
		if q == nil || q.ID == id {
			continue
		}
		if level, clash := domain.FirstOverlap(taken, q.Occupancy()); clash {
			return domain.LevelConflict(q, level)
		}
	}
	return nil
}
