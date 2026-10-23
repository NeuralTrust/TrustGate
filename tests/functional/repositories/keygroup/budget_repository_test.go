//go:build functional

package keygroup_test

import (
	"context"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/keygroup"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/keygroup"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func setupRepo(t *testing.T) (*repo.BudgetRepository, *gatewayrepo.Repository, *database.Connection) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping key group budget repository integration test")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	require.NoError(t, pool.Ping(ctx))
	conn := &database.Connection{Pool: pool}
	require.NoError(t, database.NewMigrationsManager(pool).ApplyPending(ctx))
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE key_group_budgets, gateways CASCADE")
		pool.Close()
	})
	appender := outboxrepo.NewRepository(conn)
	return repo.NewBudgetRepository(conn, appender), gatewayrepo.NewRepository(conn, appender), conn
}

func seedGateway(t *testing.T, gw *gatewayrepo.Repository, name string) ids.GatewayID {
	t.Helper()
	g, err := gatewaydomain.New(name)
	require.NoError(t, err)
	require.NoError(t, gw.Save(context.Background(), g))
	return g.ID
}

func usd(v float64) *float64 { return &v }

func budget(t *testing.T, gw ids.GatewayID, group string, monthly, member *float64, overrides map[string]float64, action string, at time.Time) *domain.Budget {
	t.Helper()
	b, err := domain.NewBudget(gw, group, monthly, member, overrides, action, at)
	require.NoError(t, err)
	return b
}

func TestBudgetRepository_UpsertReadAndDelete(t *testing.T) {
	r, gws, conn := setupRepo(t)
	ctx := context.Background()
	gw, other := seedGateway(t, gws, "kgb-g"), seedGateway(t, gws, "kgb-h")
	created := time.Now().UTC().Truncate(time.Microsecond)

	stored, err := r.Upsert(ctx, budget(t, gw, "g-eng", usd(100.25), usd(20), map[string]float64{"alice": 50, "bob": 0}, domain.ActionBlock, created))
	require.NoError(t, err)
	require.Equal(t, 100.25, *stored.MonthlyLimitUSD)
	require.Equal(t, map[string]float64{"alice": 50, "bob": 0}, stored.MemberOverrides)
	require.True(t, stored.CreatedAt.Equal(created))
	_, err = r.Upsert(ctx, budget(t, gw, "g-sre", nil, usd(5), nil, domain.ActionAlert, created))
	require.NoError(t, err)
	_, err = r.Upsert(ctx, budget(t, other, "g-eng", usd(1), nil, nil, domain.ActionAlert, created))
	require.NoError(t, err)

	replaced, err := r.Upsert(ctx, budget(t, gw, "g-eng", nil, usd(30), nil, domain.ActionAlert, created.Add(time.Hour)))
	require.NoError(t, err)
	require.Nil(t, replaced.MonthlyLimitUSD, "an upsert replaces the whole budget")
	require.Nil(t, replaced.MemberOverrides)
	require.Equal(t, 30.0, *replaced.MemberMonthlyLimitUSD)
	require.Equal(t, domain.ActionAlert, replaced.Action)
	require.True(t, replaced.CreatedAt.Equal(created), "a replaced budget keeps its creation time")
	require.True(t, replaced.UpdatedAt.Equal(created.Add(time.Hour)))

	listed, err := r.ListByGateway(ctx, gw)
	require.NoError(t, err)
	require.Len(t, listed, 2)
	require.Equal(t, "g-eng", listed[0].GroupID)
	require.Equal(t, "g-sre", listed[1].GroupID)
	all, total, err := r.List(ctx, 1, 2)
	require.NoError(t, err)
	require.Equal(t, 3, total)
	require.Len(t, all, 2)
	page2, _, err := r.List(ctx, 2, 2)
	require.NoError(t, err)
	require.Len(t, page2, 1)

	var markers int
	require.NoError(t, conn.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM config_snapshot_outbox`).Scan(&markers))
	require.Positive(t, markers, "a write asks for a new config snapshot")

	require.NoError(t, r.Delete(ctx, gw, "g-eng"))
	require.ErrorIs(t, r.Delete(ctx, gw, "g-eng"), domain.ErrNotFound)
	require.ErrorIs(t, r.Delete(ctx, gw, "g-eng"), commonerrors.ErrNotFound)
	listed, err = r.ListByGateway(ctx, gw)
	require.NoError(t, err)
	require.Len(t, listed, 1)

	_, err = r.Upsert(ctx, budget(t, ids.New[ids.GatewayKind](), "g-eng", usd(1), nil, nil, domain.ActionBlock, created))
	require.ErrorIs(t, err, commonerrors.ErrValidation, "an unknown gateway is refused")
}
