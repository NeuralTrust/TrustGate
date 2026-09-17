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

package policy_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	policymocks "github.com/NeuralTrust/TrustGate/pkg/app/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// fakeLevelLock stands in for the policy table and the lock the store takes
// over one (gateway, slug). slug is held for the whole callback, which is what
// pg_advisory_xact_lock does for the transaction: the candidates are read and
// the write lands without another writer of the same pair in between. data
// guards the stand-in table itself, so the unlocked variant is still a legal
// concurrent program.
//
// barrier, when set, releases the read phase only once that many callers have
// reached it, which reproduces the unguarded interleaving without depending on
// the scheduler.
type fakeLevelLock struct {
	slug     sync.Mutex
	data     sync.Mutex
	policies []*domain.Policy
	calls    int
	locked   bool
	barrier  *barrier
}

func newFakeLevelLock(stored ...*domain.Policy) *fakeLevelLock {
	return &fakeLevelLock{policies: stored, locked: true}
}

func (l *fakeLevelLock) WithSlugLocked(
	ctx context.Context,
	gatewayID ids.GatewayID,
	slug string,
	exclude ids.PolicyID,
	fn func(ctx context.Context, occupants []*domain.Policy) error,
) error {
	if l.locked {
		l.slug.Lock()
		defer l.slug.Unlock()
	}
	occupants := l.candidates(gatewayID, slug, exclude)
	if l.barrier != nil {
		l.barrier.wait()
	}
	return fn(ctx, occupants)
}

func (l *fakeLevelLock) candidates(gatewayID ids.GatewayID, slug string, exclude ids.PolicyID) []*domain.Policy {
	l.data.Lock()
	defer l.data.Unlock()
	l.calls++
	out := make([]*domain.Policy, 0, len(l.policies))
	for _, p := range l.policies {
		if p.GatewayID != gatewayID || p.Slug != slug || p.ID == exclude || !p.Enabled {
			continue
		}
		out = append(out, p)
	}
	return out
}

func (l *fakeLevelLock) save(p *domain.Policy) func(context.Context) error {
	return func(context.Context) error {
		l.data.Lock()
		defer l.data.Unlock()
		l.policies = append(l.policies, p)
		return nil
	}
}

func (l *fakeLevelLock) stored() int {
	l.data.Lock()
	defer l.data.Unlock()
	return len(l.policies)
}

func (l *fakeLevelLock) callCount() int {
	l.data.Lock()
	defer l.data.Unlock()
	return l.calls
}

type barrier struct {
	mu      sync.Mutex
	cond    *sync.Cond
	waiting int
	size    int
}

func newBarrier(size int) *barrier {
	b := &barrier{size: size}
	b.cond = sync.NewCond(&b.mu)
	return b
}

func (b *barrier) wait() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.waiting++
	if b.waiting >= b.size {
		b.cond.Broadcast()
		return
	}
	for b.waiting < b.size {
		b.cond.Wait()
	}
}

func noWrite(t *testing.T) func(context.Context) error {
	t.Helper()
	return func(context.Context) error {
		t.Fatal("write ran on a level the guard should have refused")
		return nil
	}
}

func TestLevelGuard_Check_WritesOnAFreeLevel(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	lock := newFakeLevelLock(unscopedPolicy(gwID, "trustguard", ids.New[ids.ConsumerKind]()))
	guard := apppolicy.NewLevelGuard(lock)

	p := unscopedPolicy(gwID, "trustguard", consumerID)
	require.NoError(t, guard.Check(context.Background(), p, lock.save(p)))
	assert.Equal(t, 2, lock.stored())
}

func TestLevelGuard_Check_RefusesAnOccupiedLevel(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	occupant := unscopedPolicy(gwID, "trustguard", consumerID)
	occupant.Name = "the first one"
	lock := newFakeLevelLock(occupant)
	guard := apppolicy.NewLevelGuard(lock)

	err := guard.Check(context.Background(), unscopedPolicy(gwID, "trustguard", consumerID), noWrite(t))
	require.ErrorIs(t, err, domain.ErrPolicyLevelConflict)
	assert.Contains(t, err.Error(), occupant.ID.String())
	assert.Contains(t, err.Error(), "the first one")
}

// A policy of another plugin is never a candidate: the rule is about two
// policies of the same plugin landing on one level.
func TestLevelGuard_Check_IgnoresAnotherPlugin(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	lock := newFakeLevelLock(unscopedPolicy(gwID, "rate_limiter", consumerID))
	guard := apppolicy.NewLevelGuard(lock)

	p := unscopedPolicy(gwID, "trustguard", consumerID)
	require.NoError(t, guard.Check(context.Background(), p, lock.save(p)))
}

func TestLevelGuard_Check_DistinctGroupsAreDistinctLevels(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	lock := newFakeLevelLock(groupScopedPolicy(gwID, "trustguard", "finance", consumerID))
	guard := apppolicy.NewLevelGuard(lock)

	p := groupScopedPolicy(gwID, "trustguard", "engineering", consumerID)
	require.NoError(t, guard.Check(context.Background(), p, lock.save(p)))
}

// A registry added to one of two policies that already name others is the
// frequent conflict, and the one an equality rule would miss.
func TestLevelGuard_Check_RefusesAPartialDestinationOverlap(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	shared := ids.New[ids.RegistryKind]()
	occupant := policyWith(gwID, "trustguard",
		&domain.MCPScope{RegistryIDs: []ids.RegistryID{ids.New[ids.RegistryKind](), shared}}, consumerID)
	lock := newFakeLevelLock(occupant)
	guard := apppolicy.NewLevelGuard(lock)

	p := policyWith(gwID, "trustguard",
		&domain.MCPScope{RegistryIDs: []ids.RegistryID{shared, ids.New[ids.RegistryKind]()}}, consumerID)
	err := guard.Check(context.Background(), p, noWrite(t))
	require.ErrorIs(t, err, domain.ErrPolicyLevelConflict)
	assert.Contains(t, err.Error(), shared.String())
}

func TestLevelGuard_Check_DisabledPolicyTakesNoLevel(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	lock := newFakeLevelLock(unscopedPolicy(gwID, "trustguard", consumerID))
	guard := apppolicy.NewLevelGuard(lock)

	p := unscopedPolicy(gwID, "trustguard", consumerID)
	p.Enabled = false
	require.NoError(t, guard.Check(context.Background(), p, lock.save(p)))
	assert.Zero(t, lock.callCount(), "a policy that takes no level must not take the lock either")
}

func TestLevelGuard_Check_DisabledOccupantIsNotCountedAgainst(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	occupant := unscopedPolicy(gwID, "trustguard", consumerID)
	occupant.Enabled = false
	lock := newFakeLevelLock(occupant)
	guard := apppolicy.NewLevelGuard(lock)

	p := unscopedPolicy(gwID, "trustguard", consumerID)
	require.NoError(t, guard.Check(context.Background(), p, lock.save(p)))
}

// Enabling is a write of its own, or the rule would be sidestepped by saving
// disabled and switching on afterwards.
func TestLevelGuard_Check_RefusesEnablingOntoAnOccupiedLevel(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	lock := newFakeLevelLock(unscopedPolicy(gwID, "trustguard", consumerID))
	guard := apppolicy.NewLevelGuard(lock)

	dormant := unscopedPolicy(gwID, "trustguard", consumerID)
	dormant.Enabled = false
	require.NoError(t, guard.Check(context.Background(), dormant, lock.save(dormant)))

	dormant.Enabled = true
	err := guard.Check(context.Background(), dormant, noWrite(t))
	require.ErrorIs(t, err, domain.ErrPolicyLevelConflict)
}

func TestLevelGuard_Check_TombstoneTakesNoLevel(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	occupant := policyWith(gwID, "trustguard", &domain.MCPScope{}, consumerID)
	lock := newFakeLevelLock(occupant)
	guard := apppolicy.NewLevelGuard(lock)

	tombstone := policyWith(gwID, "trustguard", &domain.MCPScope{}, consumerID)
	require.NoError(t, guard.Check(context.Background(), tombstone, lock.save(tombstone)))
	assert.Zero(t, lock.callCount())
}

// A global policy runs for every consumer, so it holds the wildcard consumer
// whatever is attached to it, and a second global one of the same plugin has
// nowhere to go.
func TestLevelGuard_Check_TwoGlobalsOfOnePluginCollide(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	occupant := unscopedPolicy(gwID, "trustguard", ids.New[ids.ConsumerKind]())
	occupant.Global = true
	lock := newFakeLevelLock(occupant)
	guard := apppolicy.NewLevelGuard(lock)

	promoted := unscopedPolicy(gwID, "trustguard", ids.New[ids.ConsumerKind]())
	promoted.Global = true
	err := guard.Check(context.Background(), promoted, noWrite(t))
	require.ErrorIs(t, err, domain.ErrPolicyLevelConflict)
	assert.Contains(t, err.Error(), "consumer=all group=all resource=all")
}

func TestLevelGuard_Check_PropagatesTheWriteError(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	sentinel := errors.New("write failed")
	lock := newFakeLevelLock()
	guard := apppolicy.NewLevelGuard(lock)

	err := guard.Check(context.Background(), unscopedPolicy(gwID, "trustguard", ids.New[ids.ConsumerKind]()),
		func(context.Context) error { return sentinel })
	require.ErrorIs(t, err, sentinel)
}

// Two writers racing for one level: the lock is held across the read and the
// write, so the second one sees the first and is refused. Run with -race.
func TestLevelGuard_Check_ConcurrentWritesOfOneLevel(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	lock := newFakeLevelLock()
	guard := apppolicy.NewLevelGuard(lock)

	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := unscopedPolicy(gwID, "trustguard", consumerID)
			errs[i] = guard.Check(context.Background(), p, lock.save(p))
		}()
	}
	wg.Wait()

	conflicts := 0
	for _, err := range errs {
		if err == nil {
			continue
		}
		require.ErrorIs(t, err, domain.ErrPolicyLevelConflict)
		conflicts++
	}
	assert.Equal(t, 1, conflicts, "exactly one of the two writers must be refused")
	assert.Equal(t, 1, lock.stored(), "the refused write must not have landed")
}

// The same two writers without the lock: both read the level free and both
// take it. This is what the guard would be worth if the check did not hold the
// (gateway, slug) lock until the write it authorises has landed.
func TestLevelGuard_Check_ConcurrentWritesWithoutTheLockBothLand(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	lock := newFakeLevelLock()
	lock.locked = false
	lock.barrier = newBarrier(2)
	guard := apppolicy.NewLevelGuard(lock)

	errs := make([]error, 2)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := unscopedPolicy(gwID, "trustguard", consumerID)
			errs[i] = guard.Check(context.Background(), p, lock.save(p))
		}()
	}
	wg.Wait()

	require.NoError(t, errors.Join(errs...))
	assert.Equal(t, 2, lock.stored(), "without the lock the level is taken twice")
}

// freeLevels is a guard over an empty store: every level is free, so the
// services under test go through it without the guard being what they assert.
func freeLevels(t *testing.T) apppolicy.LevelGuard {
	t.Helper()
	return apppolicy.NewLevelGuard(newFakeLevelLock())
}

// occupiedLevels is a guard whose store already holds the given policies.
func occupiedLevels(t *testing.T, stored ...*domain.Policy) apppolicy.LevelGuard {
	t.Helper()
	return apppolicy.NewLevelGuard(newFakeLevelLock(stored...))
}

// TestCreator_Create_RefusesAnOccupiedLevel is the create half of the five
// write paths: the guard sits between the validation and the store, so the row
// is never written.
func TestCreator_Create_RefusesAnOccupiedLevel(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	occupant := unscopedPolicy(gwID, "rate_limiter")
	occupant.Global = true
	repo := repomocks.NewRepository(t)
	creator := apppolicy.NewCreator(repo, occupiedLevels(t, occupant), newRegistryRepo(t), newRegistryMock(t, nil),
		newCacheManager(), newTestLogger(), nil)

	_, err := creator.Create(context.Background(), validCreateInput(gwID))
	require.ErrorIs(t, err, domain.ErrPolicyLevelConflict)
	repo.AssertNotCalled(t, "Save", mock.Anything, mock.Anything)
}

func TestCreator_Create_WritesOnAFreeLevel(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	occupant := unscopedPolicy(gwID, "rate_limiter", ids.New[ids.ConsumerKind]())
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.Anything).Return(nil).Once()
	creator := apppolicy.NewCreator(repo, occupiedLevels(t, occupant), newRegistryRepo(t), newRegistryMock(t, nil),
		newCacheManager(), newTestLogger(), nil)

	_, err := creator.Create(context.Background(), validCreateInput(gwID))
	require.NoError(t, err)
}

// An update that only turns enabled on is a write of a level, and the one that
// would sidestep the rule if it were not guarded.
func TestUpdater_Update_RefusesEnablingOntoAnOccupiedLevel(t *testing.T) {
	t.Parallel()
	existing := existingPolicy(t)
	existing.Enabled = false
	existing.ConsumerIDs = []ids.ConsumerID{ids.New[ids.ConsumerKind]()}
	occupant := unscopedPolicy(existing.GatewayID, existing.Slug, existing.ConsumerIDs[0])

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	updater := apppolicy.NewUpdater(repo, occupiedLevels(t, occupant), newRegistryRepo(t), newRegistryMock(t, nil),
		newCacheManager(), cachemocks.NewEventPublisher(t), newTestLogger(), nil)

	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{ID: existing.ID, Enabled: ptr(true)})
	require.ErrorIs(t, err, domain.ErrPolicyLevelConflict)
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
}

// Saving the replacement disabled next to the policy it will replace stays
// allowed: a disabled policy runs nowhere, so it takes no level.
func TestUpdater_Update_DisablingOntoAnOccupiedLevelIsAllowed(t *testing.T) {
	t.Parallel()
	existing := existingPolicy(t)
	existing.ConsumerIDs = []ids.ConsumerID{ids.New[ids.ConsumerKind]()}
	occupant := unscopedPolicy(existing.GatewayID, existing.Slug, existing.ConsumerIDs[0])

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().Update(mock.Anything, mock.Anything, false).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()
	updater := apppolicy.NewUpdater(repo, occupiedLevels(t, occupant), newRegistryRepo(t), newRegistryMock(t, nil),
		newCacheManager(), publisher, newTestLogger(), nil)

	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{ID: existing.ID, Enabled: ptr(false)})
	require.NoError(t, err)
}

// The promotion moves the policy to the all-traffic level, which the gateway
// may already run that plugin at.
func TestScoper_SetGlobal_RefusesAnOccupiedAllTrafficLevel(t *testing.T) {
	t.Parallel()
	existing := existingPolicy(t)
	occupant := unscopedPolicy(existing.GatewayID, existing.Slug)
	occupant.Global = true

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	scoper := apppolicy.NewScoper(repo, occupiedLevels(t, occupant), newCacheManager(),
		cachemocks.NewEventPublisher(t), newTestLogger(), nil)

	_, err := scoper.SetGlobal(context.Background(), existing.GatewayID, existing.ID)
	require.ErrorIs(t, err, domain.ErrPolicyLevelConflict)
	repo.AssertNotCalled(t, "SetGlobal", mock.Anything, mock.Anything, mock.Anything, mock.Anything)
}

// Demoting only releases levels, so it must not be refused by a guard that
// would refuse the promotion.
func TestScoper_UnsetGlobal_IsNotGuarded(t *testing.T) {
	t.Parallel()
	existing := existingPolicy(t)
	existing.Global = true
	occupant := unscopedPolicy(existing.GatewayID, existing.Slug)
	occupant.Global = true

	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	repo.EXPECT().SetGlobal(mock.Anything, existing.GatewayID, existing.ID, false).Return(nil).Once()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, mock.Anything).Return(nil).Once()
	scoper := apppolicy.NewScoper(repo, occupiedLevels(t, occupant), newCacheManager(), publisher, newTestLogger(), nil)

	_, err := scoper.UnsetGlobal(context.Background(), existing.GatewayID, existing.ID)
	require.NoError(t, err)
}

// The duplicate writes through the creator, so it carries the creator's guard
// and no second one: a copy of a policy that runs everywhere would land on the
// level its source already holds.
func TestDuplicator_Duplicate_SurfacesTheLevelConflict(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	src := sourcePolicy(gwID, "Foo")

	finder := policymocks.NewFinder(t)
	finder.EXPECT().FindByID(mock.Anything, gwID, src.ID).Return(src, nil).Once()
	finder.EXPECT().List(mock.Anything, mock.Anything).Return([]*domain.Policy{src}, 1, nil).Once()

	repo := repomocks.NewRepository(t)
	creator := apppolicy.NewCreator(repo, occupiedLevels(t, src), newRegistryRepo(t), newRegistryMock(t, nil),
		newCacheManager(), newTestLogger(), nil)

	_, err := apppolicy.NewDuplicator(finder, creator, newTestLogger()).Duplicate(context.Background(), gwID, src.ID)
	require.ErrorIs(t, err, domain.ErrPolicyLevelConflict)
	repo.AssertNotCalled(t, "Save", mock.Anything, mock.Anything)
}
