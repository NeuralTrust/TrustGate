//go:build functional

package consumer_test

import (
	"context"
	"sync"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	authrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/auth"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	policyrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/policy"
	"github.com/stretchr/testify/require"
)

type linkedConsumer struct {
	consumer *domain.Consumer
	auth     ids.AuthID
	registry ids.RegistryID
	policy   ids.PolicyID
}

func seedLinkedConsumer(t *testing.T, f fixture, gwID ids.GatewayID, name string) linkedConsumer {
	t.Helper()
	ctx := context.Background()
	appender := outboxrepo.NewRepository(f.conn)

	registryID := seedRegistry(t, f.be, gwID, name+"-reg")
	c := validConsumer(t, gwID, name, registryID)
	saveWithRegistries(t, f, c)

	key, err := authdomain.NewAPIKeyAuth(gwID, name+"-key", true, nil)
	require.NoError(t, err)
	require.NoError(t, authrepo.NewRepository(f.conn, appender).Save(ctx, key))
	require.NoError(t, f.repo.AttachAuth(ctx, c.ID, key.ID, nil))

	p, err := policydomain.NewPolicy(gwID, name+"-policy", "rate_limiter", true, 0, false,
		map[string]any{"limit": 100}, []policydomain.Stage{policydomain.StagePreRequest}, "", policydomain.ModeEnforce, nil)
	require.NoError(t, err)
	require.NoError(t, policyrepo.NewRepository(f.conn, appender).Save(ctx, p))
	require.NoError(t, f.repo.AttachPolicy(ctx, c.ID, p.ID))

	return linkedConsumer{consumer: c, auth: key.ID, registry: registryID, policy: p.ID}
}

func linkCount(t *testing.T, f fixture, consumerID ids.ConsumerID) int {
	t.Helper()
	const query = `
		SELECT (SELECT COUNT(*) FROM consumer_auth WHERE consumer_id = $1)
		     + (SELECT COUNT(*) FROM consumer_registry WHERE consumer_id = $1)
		     + (SELECT COUNT(*) FROM consumer_policy WHERE consumer_id = $1)`
	var n int
	require.NoError(t, f.conn.Pool.QueryRow(context.Background(), query, consumerID).Scan(&n))
	return n
}

func TestRepository_SoftDelete_KeepsTheRowAndDropsItsLinks(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "soft-delete-gw")
	linked := seedLinkedConsumer(t, f, gwID, "soft-delete")
	c := linked.consumer
	require.Equal(t, 3, linkCount(t, f, c.ID))

	require.NoError(t, f.repo.Delete(ctx, gwID, c.ID))

	var name string
	var deleted, updatedAfterCreate bool
	require.NoError(t, f.conn.Pool.QueryRow(ctx,
		`SELECT name, deleted_at IS NOT NULL, updated_at > created_at FROM consumers WHERE id = $1`, c.ID,
	).Scan(&name, &deleted, &updatedAfterCreate))
	require.Equal(t, c.Name, name, "the row and its fields stay as history")
	require.True(t, deleted)
	require.True(t, updatedAfterCreate)
	require.Zero(t, linkCount(t, f, c.ID), "keys, registries and policies are unlinked with the delete")

	_, err := f.repo.FindByID(ctx, c.ID)
	require.ErrorIs(t, err, domain.ErrNotFound)
	_, err = f.repo.FindSummaryByID(ctx, c.ID)
	require.ErrorIs(t, err, domain.ErrNotFound)
	_, err = f.repo.FindActiveBySlug(ctx, c.Slug)
	require.ErrorIs(t, err, domain.ErrNotFound)

	listed, total, err := f.repo.List(ctx, domain.ListFilter{GatewayID: gwID})
	require.NoError(t, err)
	require.Empty(t, listed)
	require.Zero(t, total)
	byGateway, err := f.repo.ListByGateway(ctx, gwID)
	require.NoError(t, err)
	require.Empty(t, byGateway)
	byAuth, err := f.repo.ListByAuthID(ctx, linked.auth)
	require.NoError(t, err)
	require.Empty(t, byAuth)

	require.ErrorIs(t, f.repo.Delete(ctx, gwID, c.ID), domain.ErrNotFound)
}

func TestRepository_SoftDelete_RefusesWritesToADeletedConsumer(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "soft-delete-writes-gw")
	linked := seedLinkedConsumer(t, f, gwID, "soft-delete-writes")
	c := linked.consumer
	require.NoError(t, f.repo.Delete(ctx, gwID, c.ID))

	weight := 2
	require.ErrorIs(t, f.repo.AttachAuth(ctx, c.ID, linked.auth, nil), domain.ErrNotFound)
	require.ErrorIs(t, f.repo.AttachRegistry(ctx, c.ID, linked.registry, nil), domain.ErrNotFound)
	require.ErrorIs(t, f.repo.AttachRegistry(ctx, c.ID, linked.registry, &weight), domain.ErrNotFound)
	require.ErrorIs(t, f.repo.AttachPolicy(ctx, c.ID, linked.policy), domain.ErrNotFound)
	require.ErrorIs(t, f.repo.Update(ctx, c, nil, &[]ids.AuthID{linked.auth}), domain.ErrNotFound)
	require.ErrorIs(t, f.repo.UpdateLabelSets(ctx, c), domain.ErrNotFound)
	_, err := f.repo.DetachRegistryIfUnreferenced(ctx, gwID, c.ID, linked.registry)
	require.ErrorIs(t, err, domain.ErrNotFound)
	require.Zero(t, linkCount(t, f, c.ID))
}

func TestRepository_SoftDelete_FreesTheNameAndSlug(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "soft-delete-reuse-gw")
	first := validConsumer(t, gwID, "reused")
	require.NoError(t, f.repo.Save(ctx, first))

	sameSlug := validConsumer(t, gwID, "reused-other")
	sameSlug.Slug = first.Slug
	require.ErrorIs(t, f.repo.Save(ctx, sameSlug), domain.ErrSlugAlreadyExists, "a live slug stays unique")
	sameName := validConsumer(t, gwID, "reused")
	sameName.Slug = first.Slug + "-other"
	require.ErrorIs(t, f.repo.Save(ctx, sameName), domain.ErrAlreadyExists, "a live name stays unique")

	require.NoError(t, f.repo.Delete(ctx, gwID, first.ID))
	replacement := validConsumer(t, gwID, "reused")
	replacement.Slug = first.Slug
	require.NoError(t, f.repo.Save(ctx, replacement))

	routed, err := f.repo.FindActiveBySlug(ctx, first.Slug)
	require.NoError(t, err)
	require.Equal(t, replacement.ID, routed.ID, "the slug routes to the live consumer")
}

func TestRepository_SoftDelete_GatewayDeleteRemovesDeletedConsumers(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "soft-delete-gateway-gw")
	deleted := seedLinkedConsumer(t, f, gwID, "soft-delete-gateway-deleted")
	live := seedLinkedConsumer(t, f, gwID, "soft-delete-gateway-live")
	require.NoError(t, f.repo.Delete(ctx, gwID, deleted.consumer.ID))

	require.NoError(t, f.gw.Delete(ctx, gwID))

	var remaining int
	require.NoError(t, f.conn.Pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM consumers WHERE id = ANY($1)`,
		ids.ToUUIDs([]ids.ConsumerID{deleted.consumer.ID, live.consumer.ID}),
	).Scan(&remaining))
	require.Zero(t, remaining, "a gateway delete removes its consumers, deleted ones included")
}

// TestRepository_SoftDelete_RacingLinkWritesLeaveNoLinks covers the race a hard
// delete settled through the foreign key: with the row kept, only the row lock
// keeps a link written during the delete from outliving it.
func TestRepository_SoftDelete_RacingLinkWritesLeaveNoLinks(t *testing.T) {
	f := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, f.gw, "soft-delete-race-gw")

	for i := range 10 {
		linked := seedLinkedConsumer(t, f, gwID, "soft-delete-race-"+string(rune('a'+i)))
		c := linked.consumer
		require.NoError(t, f.repo.DetachAuth(ctx, c.ID, linked.auth))
		require.NoError(t, f.repo.DetachPolicy(ctx, c.ID, linked.policy))
		require.NoError(t, f.repo.DetachRegistry(ctx, c.ID, linked.registry))

		start := make(chan struct{})
		var wg sync.WaitGroup
		writes := []func() error{
			func() error { return f.repo.AttachAuth(ctx, c.ID, linked.auth, nil) },
			func() error { return f.repo.AttachRegistry(ctx, c.ID, linked.registry, nil) },
			func() error { return f.repo.AttachPolicy(ctx, c.ID, linked.policy) },
		}
		errs := make([]error, len(writes))
		for j, write := range writes {
			wg.Go(func() {
				<-start
				errs[j] = write()
			})
		}
		var deleteErr error
		wg.Go(func() {
			<-start
			deleteErr = f.repo.Delete(ctx, gwID, c.ID)
		})
		close(start)
		wg.Wait()

		require.NoError(t, deleteErr)
		for _, err := range errs {
			if err != nil {
				require.ErrorIs(t, err, domain.ErrNotFound)
			}
		}
		require.Zero(t, linkCount(t, f, c.ID), "round %d: a link survived the delete", i)
	}
}
