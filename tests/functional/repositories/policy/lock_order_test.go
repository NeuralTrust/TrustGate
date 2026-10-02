//go:build functional

package policy_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	consumerrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/consumer"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/policy"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// namedConn opens a pool whose sessions report appName, so a test can tell from
// pg_stat_activity whether the call it runs on them is waiting on a lock.
func namedConn(t *testing.T, appName string) *database.Connection {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(os.Getenv("PG_TEST_URL"))
	if err != nil {
		t.Fatalf("parse PG_TEST_URL: %v", err)
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = appName
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		t.Fatalf("open pgxpool %s: %v", appName, err)
	}
	t.Cleanup(pool.Close)
	return &database.Connection{Pool: pool}
}

// beginHeld opens a transaction the test drives by hand, rolled back at cleanup
// unless the test commits it first.
func beginHeld(ctx context.Context, t *testing.T, conn *database.Connection) pgx.Tx {
	t.Helper()
	tx, err := conn.Pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(context.Background()) })
	return tx
}

// goJoined runs fn on its own goroutine and returns the channel its result
// arrives on. At cleanup it cancels ctx and waits for fn to return, so a test
// that fails early never rolls back a transaction or closes a pool under a call
// still running on it. It is called after beginHeld, so the join runs first.
func goJoined(t *testing.T, cancel context.CancelFunc, fn func() error) <-chan error {
	t.Helper()
	result := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		result <- fn()
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	return result
}

// waitUntilLockWait returns once a session of appName waits on a lock. done
// carries the result of the call expected to wait: one that returns first never
// waited, and the test fails on it instead of polling until ctx expires.
func waitUntilLockWait(ctx context.Context, t *testing.T, observer *database.Connection, appName string, done <-chan error) {
	t.Helper()
	const query = `SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name = $1 AND wait_event_type = 'Lock')`
	tick := time.NewTicker(10 * time.Millisecond)
	defer tick.Stop()
	for {
		var waiting bool
		if err := observer.Pool.QueryRow(ctx, query, appName).Scan(&waiting); err != nil {
			t.Fatalf("read pg_stat_activity: %v", err)
		}
		if waiting {
			return
		}
		select {
		case err := <-done:
			t.Fatalf("%s returned before it waited on a lock: %v", appName, err)
		case <-ctx.Done():
			t.Fatalf("%s never waited on a lock: %v", appName, ctx.Err())
		case <-tick.C:
		}
	}
}

// ascending orders a and b the way Postgres orders uuid values, bytewise.
func ascending(a, b uuid.UUID) (lower, higher uuid.UUID) {
	if bytes.Compare(a[:], b[:]) > 0 {
		return b, a
	}
	return a, b
}

// moveBehind rewrites the row of lower so its new version lands after the row
// of higher in the heap, which makes scan order and id order disagree. The name
// is indexed, so the update is never HOT and an index scan sees the move too.
func moveBehind(ctx context.Context, t *testing.T, conn *database.Connection, table string, gwID ids.GatewayID, lower, higher uuid.UUID) {
	t.Helper()
	if _, err := conn.Pool.Exec(ctx, fmt.Sprintf(`UPDATE %s SET name = name || '-moved' WHERE id = $1`, table), lower); err != nil {
		t.Fatalf("move %s row: %v", table, err)
	}
	rows, err := conn.Pool.Query(ctx, fmt.Sprintf(`SELECT id FROM %s WHERE gateway_id = $1 ORDER BY ctid`, table), gwID)
	if err != nil {
		t.Fatalf("read %s heap order: %v", table, err)
	}
	got, err := pgx.CollectRows(rows, pgx.RowTo[uuid.UUID])
	if err != nil {
		t.Fatalf("scan %s heap order: %v", table, err)
	}
	if len(got) != 2 || got[0] != higher || got[1] != lower {
		t.Fatalf("%s heap order = %v, want %s before %s", table, got, higher, lower)
	}
}

// A registry delete is held between its two prunes, with every consumer of the
// gateway locked and no policy yet. An attach to P, whose enabled sibling S
// names the registry, then has to wait for the consumer it links, and it must
// wait before it locks S: otherwise the policy prune that follows waits for S
// while the attach waits for the consumer, and Postgres aborts one of them.
func TestLockOrder_GuardedAttachWaitsForTheRegistryDeleteBeforeLockingPolicies(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	gwID := seedGateway(t, gw, "lock-order-attach")
	registryID := seedMCPRegistry(t, conn, gwID, "lock-order-attach-victim")
	consumerID := seedConsumer(t, conn, gwID, "lock-order-attach-consumer")
	attached := scopedPolicy(t, gwID, "attached", nil)
	sibling := scopedPolicy(t, gwID, "sibling", &domain.MCPScope{RegistryIDs: []ids.RegistryID{registryID}})
	for _, p := range []*domain.Policy{attached, sibling} {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", p.Name, err)
		}
	}

	deleteConn := namedConn(t, "lock-order-delete-"+gwID.String())
	deletion := beginHeld(ctx, t, deleteConn)
	consumers := consumerrepo.NewRepository(deleteConn, outboxrepo.NewRepository(deleteConn))
	if _, err := consumers.PruneRegistryReferencesTx(ctx, deletion, gwID, registryID); err != nil {
		t.Fatalf("consumer prune: %v", err)
	}

	writerApp := "lock-order-writer-" + gwID.String()
	writerConn := namedConn(t, writerApp)
	writerPolicies := repo.NewRepository(writerConn, outboxrepo.NewRepository(writerConn))
	writerConsumers := consumerrepo.NewRepository(writerConn, outboxrepo.NewRepository(writerConn))
	written := goJoined(t, cancel, func() error {
		return writerPolicies.WithSlugLocked(ctx, gwID, attached.Slug, attached.ID, []ids.ConsumerID{consumerID},
			func(ctx context.Context, _ []*domain.Policy) error {
				return writerConsumers.AttachPolicy(ctx, consumerID, attached.ID)
			})
	})
	waitUntilLockWait(ctx, t, conn, writerApp, written)

	report, err := r.PruneRegistryReferencesTx(ctx, deletion, gwID, registryID)
	if err != nil {
		t.Fatalf("policy prune: %v", err)
	}
	if len(report.Policies) != 1 || report.Policies[0].PolicyID != sibling.ID {
		t.Fatalf("prune report = %+v, want only the sibling", report.Policies)
	}
	if err := deletion.Commit(ctx); err != nil {
		t.Fatalf("commit registry delete: %v", err)
	}
	if err := <-written; err != nil {
		t.Fatalf("guarded attach: %v", err)
	}

	var linked bool
	if err := conn.Pool.QueryRow(ctx,
		"SELECT EXISTS (SELECT 1 FROM consumer_policy WHERE consumer_id = $1 AND policy_id = $2)",
		consumerID, attached.ID,
	).Scan(&linked); err != nil {
		t.Fatalf("read consumer_policy: %v", err)
	}
	if !linked {
		t.Fatal("the attach returned nil but the link is not stored")
	}
}

// A guarded write of P is held after WithSlugLocked has taken its locks and
// before it rewrites P. A registry delete then prunes P and its sibling S, both
// naming the registry. The write must already hold P: a prune that reached P
// first would wait for S while the write waits for P, and Postgres would abort
// one of them.
func TestLockOrder_GuardedWriteHoldsItsOwnRowBeforeTheRegistryDelete(t *testing.T) {
	rewrite := func(ctx context.Context, r *repo.Repository, p *domain.Policy) error {
		p.Description = "rewritten under the slug lock"
		return r.Update(ctx, p, false)
	}
	cases := []struct {
		name       string
		slugChange bool
		write      func(ctx context.Context, r *repo.Repository, p *domain.Policy) error
		landed     func(got *domain.Policy) bool
	}{
		{
			name:   "update",
			write:  rewrite,
			landed: func(got *domain.Policy) bool { return got.Description == "rewritten under the slug lock" },
		},
		{
			name: "promotion",
			write: func(ctx context.Context, r *repo.Repository, p *domain.Policy) error {
				return r.SetGlobal(ctx, p.GatewayID, p.ID, true)
			},
			landed: func(got *domain.Policy) bool { return got.Global },
		},
		{
			// The row still carries its old slug when the locks are taken, so
			// only its id puts it among the rows locked up front.
			name:       "update that changes the slug",
			slugChange: true,
			write:      rewrite,
			landed:     func(got *domain.Policy) bool { return got.Slug == "trustguard" },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, gw, conn := setupRepo(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			gwID := seedGateway(t, gw, "lock-order-write")
			registryID := seedMCPRegistry(t, conn, gwID, "lock-order-write-victim")
			target := scopedPolicy(t, gwID, "written", &domain.MCPScope{RegistryIDs: []ids.RegistryID{registryID}})
			sibling := scopedPolicy(t, gwID, "sibling", &domain.MCPScope{RegistryIDs: []ids.RegistryID{registryID}})
			// P sorts and is stored before S, so a prune that locks in id order
			// or in heap order alike reaches P first and then waits for S.
			if a, b := target.ID.UUID(), sibling.ID.UUID(); bytes.Compare(a[:], b[:]) > 0 {
				target.ID, sibling.ID = sibling.ID, target.ID
			}
			if tc.slugChange {
				target.Slug = "rate_limiter"
			}
			for _, p := range []*domain.Policy{target, sibling} {
				if err := r.Save(ctx, p); err != nil {
					t.Fatalf("Save %s: %v", p.Name, err)
				}
			}

			deleteApp := "lock-order-delete-" + gwID.String()
			deleteConn := namedConn(t, deleteApp)
			deletion := beginHeld(ctx, t, deleteConn)

			writerConn := namedConn(t, "lock-order-writer-"+gwID.String())
			writer := repo.NewRepository(writerConn, outboxrepo.NewRepository(writerConn))
			stored := *target
			stored.Slug = sibling.Slug
			locked, release := make(chan struct{}), make(chan struct{})
			written := goJoined(t, cancel, func() error {
				return writer.WithSlugLocked(ctx, gwID, stored.Slug, stored.ID, nil,
					func(ctx context.Context, _ []*domain.Policy) error {
						close(locked)
						select {
						case <-release:
						case <-ctx.Done():
							return ctx.Err()
						}
						return tc.write(ctx, writer, &stored)
					})
			})
			select {
			case <-locked:
			case err := <-written:
				t.Fatalf("guarded %s returned before it took its locks: %v", tc.name, err)
			}

			consumers := consumerrepo.NewRepository(deleteConn, outboxrepo.NewRepository(deleteConn))
			if _, err := consumers.PruneRegistryReferencesTx(ctx, deletion, gwID, registryID); err != nil {
				t.Fatalf("consumer prune: %v", err)
			}
			var report registrydomain.PruneReport
			pruned := goJoined(t, cancel, func() error {
				var err error
				report, err = r.PruneRegistryReferencesTx(ctx, deletion, gwID, registryID)
				return err
			})
			waitUntilLockWait(ctx, t, conn, deleteApp, pruned)

			close(release)
			for range 2 {
				select {
				case err := <-written:
					if err != nil {
						t.Fatalf("guarded %s: %v", tc.name, err)
					}
				case err := <-pruned:
					if err != nil {
						t.Fatalf("policy prune: %v", err)
					}
				}
			}
			if err := deletion.Commit(ctx); err != nil {
				t.Fatalf("commit registry delete: %v", err)
			}
			if len(report.Policies) != 2 {
				t.Fatalf("prune report = %+v, want both policies", report.Policies)
			}

			got, err := r.FindByID(ctx, target.ID)
			if err != nil {
				t.Fatalf("FindByID: %v", err)
			}
			if !tc.landed(got) {
				t.Fatalf("the guarded %s did not land: %+v", tc.name, got)
			}
			for _, id := range []ids.PolicyID{target.ID, sibling.ID} {
				if isNull, text := rawMCPScope(t, conn, id); isNull || text != "{}" {
					t.Fatalf("scope of %s = (null=%v, %q), want the registry pruned to '{}'", id, isNull, text)
				}
			}
		})
	}
}

// A gateway delete locks the gateway's consumers in ascending id, as a registry
// delete does. Its DELETE alone locks them in scan order, which an update of
// the lower id turns into the higher id first: the gateway delete would then
// hold the higher id and wait on the lower one, which the registry delete holds
// while it waits on the higher one.
//
// The higher id is held elsewhere first, so the gateway delete queues on it
// ahead of the registry delete and takes it the moment it is released.
func TestLockOrder_GatewayDeleteLocksConsumersInIDOrder(t *testing.T) {
	_, gw, conn := setupRepo(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	gwID := seedGateway(t, gw, "lock-order-gateway")
	registryID := seedMCPRegistry(t, conn, gwID, "lock-order-gateway-victim")
	lower, higher := ascending(
		seedConsumer(t, conn, gwID, "lock-order-gateway-a").UUID(),
		seedConsumer(t, conn, gwID, "lock-order-gateway-b").UUID(),
	)
	moveBehind(ctx, t, conn, "consumers", gwID, lower, higher)

	blocker := beginHeld(ctx, t, conn)
	if _, err := blocker.Exec(ctx, `SELECT 1 FROM consumers WHERE id = $1 FOR UPDATE`, higher); err != nil {
		t.Fatalf("hold the higher consumer: %v", err)
	}
	gatewayApp := "lock-order-gateway-delete-" + gwID.String()
	gatewayConn := namedConn(t, gatewayApp)
	pruneApp := "lock-order-delete-" + gwID.String()
	pruneConn := namedConn(t, pruneApp)
	deletion := beginHeld(ctx, t, pruneConn)

	gateways := gatewayrepo.NewRepository(gatewayConn, outboxrepo.NewRepository(gatewayConn))
	deleted := goJoined(t, cancel, func() error { return gateways.Delete(ctx, gwID) })
	waitUntilLockWait(ctx, t, conn, gatewayApp, deleted)

	consumers := consumerrepo.NewRepository(pruneConn, outboxrepo.NewRepository(pruneConn))
	policies := repo.NewRepository(pruneConn, outboxrepo.NewRepository(pruneConn))
	pruned := goJoined(t, cancel, func() error {
		if _, err := consumers.PruneRegistryReferencesTx(ctx, deletion, gwID, registryID); err != nil {
			return fmt.Errorf("consumer prune: %w", err)
		}
		if _, err := policies.PruneRegistryReferencesTx(ctx, deletion, gwID, registryID); err != nil {
			return fmt.Errorf("policy prune: %w", err)
		}
		return nil
	})
	waitUntilLockWait(ctx, t, conn, pruneApp, pruned)

	if err := blocker.Rollback(ctx); err != nil {
		t.Fatalf("release the higher consumer: %v", err)
	}
	for range 2 {
		select {
		case err := <-deleted:
			if err != nil {
				t.Fatalf("gateway delete: %v", err)
			}
		case err := <-pruned:
			if err != nil {
				t.Fatalf("registry delete: %v", err)
			}
		}
	}
	if err := deletion.Commit(ctx); err != nil {
		t.Fatalf("commit registry delete: %v", err)
	}
	if _, err := gw.FindByID(ctx, gwID); !errors.Is(err, gatewaydomain.ErrNotFound) {
		t.Fatalf("gateway FindByID after delete err = %v, want ErrNotFound", err)
	}
}

type pruneFixture struct {
	r          *repo.Repository
	conn       *database.Connection
	gwID       ids.GatewayID
	registryID ids.RegistryID
}

// ORDER BY id orders the acquisition and not only the rows returned. With the
// lower id moved behind the higher one in the heap and held elsewhere, a prune
// waits on the lower id before it has locked the higher one, so a third session
// can still take the higher one at once. A prune locking in scan order would
// already hold it.
func TestLockOrder_RegistryPrunesLockInIDOrderNotScanOrder(t *testing.T) {
	cases := []struct {
		name  string
		table string
		probe string
		seed  func(ctx context.Context, t *testing.T, f pruneFixture) (uuid.UUID, uuid.UUID)
		prune func(ctx context.Context, tx pgx.Tx, f pruneFixture) error
	}{
		{
			name:  "consumer prune",
			table: "consumers",
			probe: `SELECT 1 FROM consumers WHERE id = $1 FOR KEY SHARE NOWAIT`,
			seed: func(_ context.Context, t *testing.T, f pruneFixture) (uuid.UUID, uuid.UUID) {
				return seedConsumer(t, f.conn, f.gwID, "lock-order-scan-a").UUID(),
					seedConsumer(t, f.conn, f.gwID, "lock-order-scan-b").UUID()
			},
			prune: func(ctx context.Context, tx pgx.Tx, f pruneFixture) error {
				consumers := consumerrepo.NewRepository(f.conn, outboxrepo.NewRepository(f.conn))
				_, err := consumers.PruneRegistryReferencesTx(ctx, tx, f.gwID, f.registryID)
				return err
			},
		},
		{
			name:  "policy prune",
			table: "policies",
			probe: `SELECT 1 FROM policies WHERE id = $1 FOR UPDATE NOWAIT`,
			seed: func(ctx context.Context, t *testing.T, f pruneFixture) (uuid.UUID, uuid.UUID) {
				seeded := make([]uuid.UUID, 0, 2)
				for _, name := range []string{"lock-order-scan-a", "lock-order-scan-b"} {
					p := scopedPolicy(t, f.gwID, name, &domain.MCPScope{RegistryIDs: []ids.RegistryID{f.registryID}})
					if err := f.r.Save(ctx, p); err != nil {
						t.Fatalf("Save %s: %v", name, err)
					}
					seeded = append(seeded, p.ID.UUID())
				}
				return seeded[0], seeded[1]
			},
			prune: func(ctx context.Context, tx pgx.Tx, f pruneFixture) error {
				_, err := f.r.PruneRegistryReferencesTx(ctx, tx, f.gwID, f.registryID)
				return err
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, gw, conn := setupRepo(t)
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()

			gwID := seedGateway(t, gw, "lock-order-scan")
			f := pruneFixture{r: r, conn: conn, gwID: gwID, registryID: seedMCPRegistry(t, conn, gwID, "lock-order-scan-victim")}
			lower, higher := ascending(tc.seed(ctx, t, f))
			moveBehind(ctx, t, conn, tc.table, gwID, lower, higher)

			holder := beginHeld(ctx, t, conn)
			if _, err := holder.Exec(ctx, fmt.Sprintf(`SELECT 1 FROM %s WHERE id = $1 FOR UPDATE`, tc.table), lower); err != nil {
				t.Fatalf("hold the lower id: %v", err)
			}
			pruneApp := "lock-order-scan-prune-" + gwID.String()
			pruneConn := namedConn(t, pruneApp)
			deletion := beginHeld(ctx, t, pruneConn)

			pruned := goJoined(t, cancel, func() error { return tc.prune(ctx, deletion, f) })
			waitUntilLockWait(ctx, t, conn, pruneApp, pruned)

			if _, err := conn.Pool.Exec(ctx, tc.probe, higher); err != nil {
				t.Fatalf("lock the higher id while the %s waits on the lower one: %v", tc.name, err)
			}
			if err := holder.Rollback(ctx); err != nil {
				t.Fatalf("release the lower id: %v", err)
			}
			if err := <-pruned; err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			if err := deletion.Commit(ctx); err != nil {
				t.Fatalf("commit registry delete: %v", err)
			}
		})
	}
}
