//go:build functional

package policy_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/policy"
)

// TestLevelGuard_ConcurrentWritesOfOneLevel is the claim the guard rests on:
// two writers racing for the same level against a real Postgres, one of them
// refused. The lock the store takes is what decides it — with the check in one
// transaction and the write in another, both writers read the level free,
// because two inserts have no row to lock each other on.
func TestLevelGuard_ConcurrentWritesOfOneLevel(t *testing.T) {
	r, gw, _ := setupRepo(t)
	gwID := seedGateway(t, gw, "level-lock-race")
	guard := apppolicy.NewLevelGuard(r)

	const writers = 2
	errs := make([]error, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := validPolicy(t, gwID, "racer")
			p.Name = p.ID.String()
			// Global, so the racers occupy a level at all. A policy with no
			// consumers and no global flag is a draft, and a draft occupies
			// nothing — the guard would short-circuit before taking the lock
			// and both writes would land, which is correct and not what this
			// test is about.
			p.Global = true
			<-start
			errs[i] = guard.Check(context.Background(), p, func(ctx context.Context) error {
				return r.Save(ctx, p)
			})
		}()
	}
	close(start)
	wg.Wait()

	conflicts, stored := 0, 0
	for _, err := range errs {
		switch {
		case err == nil:
			stored++
		case errors.Is(err, domain.ErrPolicyLevelConflict):
			conflicts++
		default:
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if stored != 1 || conflicts != writers-1 {
		t.Fatalf("stored = %d, conflicts = %d, want 1 and %d", stored, conflicts, writers-1)
	}

	items, err := r.ListByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("ListByGateway: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("stored %d policies, want 1: the refused write landed anyway", len(items))
	}
}

func TestLevelLock_WithSlugLocked_ReadsTheCandidatesOfThatSlugOnly(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "level-lock-candidates")
	otherGwID := seedGateway(t, gw, "level-lock-candidates-other")

	sameSlug := validPolicy(t, gwID, "same slug")
	disabled := validPolicy(t, gwID, "disabled")
	disabled.Enabled = false
	otherSlug := scopedPolicy(t, gwID, "other slug", nil)
	otherGateway := validPolicy(t, otherGwID, "other gateway")
	excluded := validPolicy(t, gwID, "the one being written")
	for _, p := range []*domain.Policy{sameSlug, disabled, otherSlug, otherGateway, excluded} {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", p.Name, err)
		}
	}
	if _, err := conn.Pool.Exec(ctx,
		"INSERT INTO consumer_policy (consumer_id, policy_id) VALUES ($1, $2)",
		seedConsumer(t, conn, gwID, "level-lock-consumer"), sameSlug.ID,
	); err != nil {
		t.Fatalf("attach consumer: %v", err)
	}

	var got []*domain.Policy
	if err := r.WithSlugLocked(ctx, gwID, sameSlug.Slug, excluded.ID,
		func(_ context.Context, occupants []*domain.Policy) error {
			got = occupants
			return nil
		}); err != nil {
		t.Fatalf("WithSlugLocked: %v", err)
	}

	if len(got) != 1 || got[0].ID != sameSlug.ID {
		t.Fatalf("candidates = %v, want only %s", policyIDs(got), sameSlug.ID)
	}
	if len(got[0].ConsumerIDs) != 1 {
		t.Fatalf("candidate consumer ids = %v, want the attached one", got[0].ConsumerIDs)
	}
	if got[0].Occupancy().Len() != 1 {
		t.Fatalf("candidate occupancy = %d levels, want 1", got[0].Occupancy().Len())
	}
}

// The write runs in the transaction the lock opened, so a failure after it
// takes the policy with it: the check and the write it authorised commit
// together or not at all.
func TestLevelLock_WithSlugLocked_TheWriteJoinsTheTransaction(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "level-lock-rollback")
	sentinel := errors.New("write failed")
	p := validPolicy(t, gwID, "rolled back")

	err := r.WithSlugLocked(ctx, gwID, p.Slug, p.ID,
		func(txCtx context.Context, _ []*domain.Policy) error {
			if err := r.Save(txCtx, p); err != nil {
				t.Fatalf("Save: %v", err)
			}
			return sentinel
		})
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want the write error", err)
	}

	items, err := r.ListByGateway(ctx, gwID)
	if err != nil {
		t.Fatalf("ListByGateway: %v", err)
	}
	if len(items) != 0 {
		t.Fatalf("stored %d policies, want none: the write did not roll back with the lock", len(items))
	}
}

var _ apppolicy.LevelLock = (*repo.Repository)(nil)

// TestLevelGuard_ConcurrentDraftsBothLand is the other half of the rule its
// sibling relies on. A policy with no consumers and no global flag runs
// nowhere, so it occupies no level, so the guard does not take the lock and
// does not refuse it. Two of them racing must both land — otherwise creating
// two policies of one plugin would conflict before either could ever run, and
// duplicating a policy would answer 409 every time.
func TestLevelGuard_ConcurrentDraftsBothLand(t *testing.T) {
	r, gw, _ := setupRepo(t)
	gwID := seedGateway(t, gw, "level-lock-drafts")
	guard := apppolicy.NewLevelGuard(r)

	const writers = 2
	errs := make([]error, writers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p := validPolicy(t, gwID, "drafter")
			p.Name = p.ID.String()
			<-start
			errs[i] = guard.Check(context.Background(), p, func(ctx context.Context) error {
				return r.Save(ctx, p)
			})
		}()
	}
	close(start)
	wg.Wait()

	for _, err := range errs {
		if err != nil {
			t.Fatalf("a draft occupies no level, so it cannot conflict: %v", err)
		}
	}
	items, err := r.ListByGateway(context.Background(), gwID)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(items) != writers {
		t.Fatalf("stored %d drafts, want %d", len(items), writers)
	}
}
