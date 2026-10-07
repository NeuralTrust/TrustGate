//go:build functional

package auth_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/auth"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func setupRepo(t *testing.T) (*repo.Repository, *gatewayrepo.Repository) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping auth repository integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatalf("parse PG_TEST_URL: %v", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("open pgxpool: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping: %v", err)
	}

	conn := &database.Connection{Pool: pool}
	manager := database.NewMigrationsManager(pool)
	if err := manager.ApplyPending(ctx); err != nil {
		pool.Close()
		t.Fatalf("apply migrations: %v", err)
	}

	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE auths, gateways CASCADE")
		pool.Close()
	})

	appender := outboxrepo.NewRepository(conn)
	return repo.NewRepository(conn, appender), gatewayrepo.NewRepository(conn, appender)
}

func seedGateway(t *testing.T, gw *gatewayrepo.Repository, name string) ids.GatewayID {
	t.Helper()
	g, err := gatewaydomain.New(name)
	if err != nil {
		t.Fatalf("gateway domain.New: %v", err)
	}
	if err := gw.Save(context.Background(), g); err != nil {
		t.Fatalf("gateway Save: %v", err)
	}
	return g.ID
}

func validAuth(t *testing.T, gwID ids.GatewayID, name string) *domain.Auth {
	t.Helper()
	a, err := domain.NewAPIKeyAuth(gwID, name, true, nil)
	if err != nil {
		t.Fatalf("auth domain.NewAPIKeyAuth: %v", err)
	}
	return a
}

func validIDPAuth(t *testing.T, gwID ids.GatewayID, name string, enabled bool) *domain.Auth {
	t.Helper()
	// Built through the deprecated alias on purpose: NewAuth canonicalizes it,
	// so this also covers that a row written that way is found by a query for
	// the canonical type.
	a, err := domain.NewAuth(gwID, name, domain.TypeOIDC, enabled, domain.Config{OAuth2: &domain.OAuth2Config{
		Issuer:     "https://issuer.example.com",
		Audiences:  []string{"gateway"},
		JWKSURL:    "https://issuer.example.com/.well-known/jwks.json",
		Algorithms: []string{"RS256"},
	}})
	if err != nil {
		t.Fatalf("auth domain.NewAuth: %v", err)
	}
	return a
}

func TestRepository_SaveAndFindByID(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw")

	a := validAuth(t, gwID, "client-key")
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != a.ID || got.GatewayID != gwID || got.Name != "client-key" {
		t.Fatalf("FindByID returned %+v", got)
	}
	if got.Type != domain.TypeAPIKey {
		t.Fatalf("type round-trip lost data: %+v", got)
	}
	if got.KeyHash == "" || got.KeyHash != a.KeyHash {
		t.Fatalf("key_hash round-trip lost data: got %q want %q", got.KeyHash, a.KeyHash)
	}
	if got.KeyPrefix != a.KeyPrefix || got.KeySuffix != a.KeySuffix {
		t.Fatalf("key preview round-trip lost data: got %q…%q want %q…%q",
			got.KeyPrefix, got.KeySuffix, a.KeyPrefix, a.KeySuffix)
	}
}

func TestRepository_FindByAPIKeyHash(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-hash")

	a := validAuth(t, gwID, "lookup-key")
	if a.RawKey == "" {
		t.Fatalf("generated auth missing raw key for assertion")
	}
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByAPIKeyHash(ctx, domain.HashAPIKey(a.RawKey))
	if err != nil {
		t.Fatalf("FindByAPIKeyHash: %v", err)
	}
	if got.ID != a.ID || got.Type != domain.TypeAPIKey {
		t.Fatalf("FindByAPIKeyHash returned %+v", got)
	}
}

func TestRepository_FindByAPIKeyHash_NotFound(t *testing.T) {
	r, _ := setupRepo(t)
	_, err := r.FindByAPIKeyHash(context.Background(), domain.HashAPIKey("ag_nonexistent"))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_ListEnabledByGatewayAndType(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-idp")
	otherGwID := seedGateway(t, gw, "agw-idp-other")

	enabled := validIDPAuth(t, gwID, "enabled-idp", true)
	for _, a := range []*domain.Auth{
		enabled,
		validIDPAuth(t, gwID, "disabled-idp", false),
		validAuth(t, gwID, "api-key"),
		validIDPAuth(t, otherGwID, "other-idp", true),
	} {
		if err := r.Save(ctx, a); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	got, err := r.ListEnabledByGatewayAndType(ctx, gwID, domain.TypeOAuth2)
	if err != nil {
		t.Fatalf("ListEnabledByGatewayAndType: %v", err)
	}
	if len(got) != 1 || got[0].ID != enabled.ID {
		t.Fatalf("got %+v, want only enabled idp", got)
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	r, _ := setupRepo(t)
	_, err := r.FindByID(context.Background(), ids.New[ids.AuthKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("err = %v, want it to wrap commonerrors.ErrNotFound", err)
	}
}

func TestRepository_Save_DuplicateNameForSameGateway(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-dup")

	// Auth names are display labels only — credentials resolve by id / key_hash,
	// so two api_key auths on the same gateway may share a name.
	first := validAuth(t, gwID, "dupe")
	if err := r.Save(ctx, first); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	second := validAuth(t, gwID, "dupe")
	if err := r.Save(ctx, second); err != nil {
		t.Fatalf("second Save with duplicate name: %v", err)
	}
	if first.ID == second.ID {
		t.Fatalf("expected distinct auth ids for duplicate names, both %s", first.ID)
	}
}

func TestRepository_Save_InvalidGatewayID(t *testing.T) {
	r, _ := setupRepo(t)
	err := r.Save(context.Background(), validAuth(t, ids.New[ids.GatewayKind](), "orphan"))
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestRepository_Update(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-upd")

	a := validAuth(t, gwID, "alpha")
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}

	a.Name = "alpha-renamed"
	a.Type = domain.TypeOAuth2
	a.Config = domain.Config{OAuth2: &domain.OAuth2Config{
		Issuer:    "https://issuer",
		Audiences: []string{"gateway"},
		JWKSURL:   "https://issuer/.well-known/jwks.json",
	}}
	a.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, a); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "alpha-renamed" || got.Type != domain.TypeOAuth2 {
		t.Fatalf("update not persisted: %+v", got)
	}
	if got.Config.OAuth2 == nil || got.Config.OAuth2.Issuer != "https://issuer" {
		t.Fatalf("oauth2 config not persisted: %+v", got.Config)
	}
}

// Update used to write neither the key preview nor an expiry, so a rotated key
// kept the masked head and tail of the secret it replaced and an expiry could
// not be changed at all.
func TestRepository_Update_PersistsRotatedPreviewAndExpiry(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-rotate")

	a := validAuth(t, gwID, "rotating")
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if _, err := a.RotateAPIKey(time.Now().UTC()); err != nil {
		t.Fatalf("RotateAPIKey: %v", err)
	}
	expiry := time.Now().UTC().Add(72 * time.Hour).Truncate(time.Second)
	if err := a.SetExpiry(&expiry, time.Now().UTC()); err != nil {
		t.Fatalf("SetExpiry: %v", err)
	}
	if err := r.Update(ctx, a); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID after rotation: %v", err)
	}
	if got.KeyHash != domain.HashAPIKey(a.RawKey) {
		t.Fatalf("key_hash not rotated: %q", got.KeyHash)
	}
	wantPrefix, wantSuffix := domain.APIKeyPreview(a.RawKey)
	if got.KeyPrefix != wantPrefix || got.KeySuffix != wantSuffix {
		t.Fatalf("preview = %q…%q, want the rotated key's %q…%q", got.KeyPrefix, got.KeySuffix, wantPrefix, wantSuffix)
	}
	if got.ExpiresAt == nil || !got.ExpiresAt.Equal(expiry) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, expiry)
	}

	if err := a.SetExpiry(nil, time.Now().UTC()); err != nil {
		t.Fatalf("SetExpiry(nil): %v", err)
	}
	if err := r.Update(ctx, a); err != nil {
		t.Fatalf("Update clearing expiry: %v", err)
	}
	got, err = r.FindByID(ctx, a.ID)
	if err != nil {
		t.Fatalf("FindByID after clearing: %v", err)
	}
	if got.ExpiresAt != nil {
		t.Fatalf("ExpiresAt = %v, want it cleared", got.ExpiresAt)
	}
}

func TestRepository_Update_NotFound(t *testing.T) {
	r, gw := setupRepo(t)
	gwID := seedGateway(t, gw, "agw-upd2")
	err := r.Update(context.Background(), validAuth(t, gwID, "ghost"))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-del")

	a := validAuth(t, gwID, "victim")
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := r.Delete(ctx, gwID, a.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.FindByID(ctx, a.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_FindByIDs(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-ids")

	a1 := validAuth(t, gwID, "k1")
	a2 := validAuth(t, gwID, "k2")
	for _, a := range []*domain.Auth{a1, a2} {
		if err := r.Save(ctx, a); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	found, err := r.FindByIDs(ctx, gwID, []ids.AuthID{a1.ID, a2.ID})
	if err != nil {
		t.Fatalf("FindByIDs: %v", err)
	}
	if len(found) != 2 {
		t.Fatalf("FindByIDs len = %d, want 2", len(found))
	}
}

func TestRepository_List_FilterByGatewayAndName(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, gw, "agw-l1")
	gw2 := seedGateway(t, gw, "agw-l2")

	mustSave := func(a *domain.Auth) {
		if err := r.Save(ctx, a); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	mustSave(validAuth(t, gw1, "prod-key"))
	mustSave(validAuth(t, gw1, "staging-key"))
	mustSave(validAuth(t, gw2, "other-key"))

	items, total, err := r.List(ctx, domain.ListFilter{GatewayID: gw1, Page: listing.Page{Number: 1, Size: 10}})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("List(gw1) total=%d len=%d, want 2/2", total, len(items))
	}

	items, total, err = r.List(ctx, domain.ListFilter{Search: "other", Page: listing.Page{Number: 1, Size: 10}})
	if err != nil {
		t.Fatalf("List name: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Name != "other-key" {
		t.Fatalf("List(name) returned %+v", items)
	}
}

func ownedAuth(t *testing.T, gwID ids.GatewayID, owner string) *domain.Auth {
	t.Helper()
	a := validAuth(t, gwID, "personal-"+owner)
	a.OwnerID = owner
	return a
}

func TestRepository_FindByOwnerAndUpdateKeepsOwner(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwG, gwH := seedGateway(t, gw, "owner-g"), seedGateway(t, gw, "owner-h")
	application, owned := validAuth(t, gwG, "application"), ownedAuth(t, gwG, "alice")
	require.NoError(t, r.Save(ctx, application))
	require.NoError(t, r.Save(ctx, owned))

	got, err := r.FindByOwner(ctx, gwG, "alice")
	require.NoError(t, err)
	require.Equal(t, owned.ID, got.ID)
	require.Equal(t, owned.KeyHash, got.KeyHash)
	_, err = r.FindByOwner(ctx, gwH, "alice")
	require.ErrorIs(t, err, domain.ErrNotFound)
	_, err = r.FindByOwner(ctx, gwG, "bob")
	require.ErrorIs(t, err, domain.ErrNotFound)
	_, err = r.FindByOwner(ctx, gwG, "")
	require.ErrorIs(t, err, domain.ErrNotFound)

	for id, want := range map[ids.AuthID]string{owned.ID: "alice", application.ID: ""} {
		got, err := r.FindByID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, want, got.OwnerID)
		got.Name, got.OwnerID, got.UpdatedAt = "renamed", "mallory", time.Now().UTC()
		require.NoError(t, r.Update(ctx, got))
		after, err := r.FindByID(ctx, id)
		require.NoError(t, err)
		require.Equal(t, "renamed", after.Name)
		require.Equal(t, want, after.OwnerID)
	}
}

func TestRepository_ConcurrentOwnedKeysForOneOwner(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "owner-race")

	start := make(chan struct{})
	errs := make(chan error, 2)
	for range 2 {
		a := ownedAuth(t, gwID, "alice")
		go func() {
			<-start
			errs <- r.Save(ctx, a)
		}()
	}
	close(start)
	first, second := <-errs, <-errs
	if first != nil {
		first, second = second, first
	}
	require.NoError(t, first)
	require.ErrorIs(t, second, domain.ErrOwnedKeyExists)
	require.ErrorIs(t, second, commonerrors.ErrAlreadyExists)
	_, total, err := r.List(ctx, domain.ListFilter{GatewayID: gwID})
	require.NoError(t, err)
	require.Equal(t, 1, total)
}

func TestRepository_List_OwnedKeyFilters(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "owner-list")
	for _, name := range []string{"app-1", "app-2", "app-3"} {
		require.NoError(t, r.Save(ctx, validAuth(t, gwID, name)))
	}
	alice := ownedAuth(t, gwID, "alice")
	require.NoError(t, r.Save(ctx, alice))
	require.NoError(t, r.Save(ctx, ownedAuth(t, gwID, "bob")))

	for name, tc := range map[string]struct {
		filter       domain.ListFilter
		total, items int
	}{
		"default lists every key":   {filter: domain.ListFilter{}, total: 5, items: 5},
		"exclude owned":             {filter: domain.ListFilter{ExcludeOwned: true}, total: 3, items: 3},
		"exclude owned on page two": {filter: domain.ListFilter{ExcludeOwned: true, Page: listing.Page{Number: 2, Size: 2}}, total: 3, items: 1},
		"one owner":                 {filter: domain.ListFilter{OwnerID: "alice"}, total: 1, items: 1},
		"owner without a key":       {filter: domain.ListFilter{OwnerID: "carol"}, total: 0, items: 0},
		"only owned":                {filter: domain.ListFilter{OnlyOwned: true}, total: 2, items: 2},
		"only owned on page two":    {filter: domain.ListFilter{OnlyOwned: true, Page: listing.Page{Number: 2, Size: 1}}, total: 2, items: 1},
	} {
		t.Run(name, func(t *testing.T) {
			tc.filter.GatewayID = gwID
			items, total, err := r.List(ctx, tc.filter)
			require.NoError(t, err)
			require.Equal(t, tc.total, total)
			require.Len(t, items, tc.items)
			for _, a := range items {
				require.False(t, tc.filter.ExcludeOwned && a.IsOwned(), "owned key %s listed", a.ID)
				require.False(t, tc.filter.OnlyOwned && !a.IsOwned(), "application key %s listed", a.ID)
				require.True(t, tc.filter.OwnerID == "" || (a.ID == alice.ID && a.OwnerID == "alice"), "unexpected key %s", a.ID)
			}
		})
	}
}

func TestRepository_BudgetIsReadEverywhereAnAuthIs(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "budget-read")
	application, owned := validAuth(t, gwID, "application"), ownedAuth(t, gwID, "alice")
	owned.Budget = &domain.KeyBudget{Max: 12.5, Unit: domain.BudgetUnitDollars, TimeWindow: domain.BudgetWindowCalendarDay}
	require.NoError(t, r.Save(ctx, application))
	require.NoError(t, r.Save(ctx, owned))

	byID, err := r.FindByID(ctx, owned.ID)
	require.NoError(t, err)
	byHash, err := r.FindByAPIKeyHash(ctx, owned.KeyHash)
	require.NoError(t, err)
	byOwner, err := r.FindByOwner(ctx, gwID, "alice")
	require.NoError(t, err)
	byIDs, err := r.FindByIDs(ctx, gwID, []ids.AuthID{owned.ID})
	require.NoError(t, err)
	require.Len(t, byIDs, 1)
	listed, _, err := r.List(ctx, domain.ListFilter{GatewayID: gwID, OnlyOwned: true})
	require.NoError(t, err)
	require.Len(t, listed, 1)
	enabled, err := r.ListEnabledByGatewayAndType(ctx, gwID, domain.TypeAPIKey)
	require.NoError(t, err)
	require.Len(t, enabled, 1, "personal keys are not application credentials")
	require.Equal(t, application.ID, enabled[0].ID)
	require.Nil(t, enabled[0].Budget)
	for _, a := range []*domain.Auth{byID, byHash, byOwner, byIDs[0], listed[0]} {
		require.Equal(t, owned.Budget, a.Budget)
	}
	got, err := r.FindByID(ctx, application.ID)
	require.NoError(t, err)
	require.Nil(t, got.Budget)
}

func TestRepository_UpdateBudgetWritesOnlyTheBudget(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID, otherGW := seedGateway(t, gw, "budget-write"), seedGateway(t, gw, "budget-other")
	owned := ownedAuth(t, gwID, "alice")
	require.NoError(t, r.Save(ctx, owned))

	stale, err := r.FindByID(ctx, owned.ID)
	require.NoError(t, err)
	rotated, err := r.FindByID(ctx, owned.ID)
	require.NoError(t, err)
	previousHash, err := rotated.RotateAPIKey(time.Now())
	require.NoError(t, err)
	require.NoError(t, r.Update(ctx, rotated))

	monthly := &domain.KeyBudget{Max: 50, Unit: domain.BudgetUnitDollars, TimeWindow: domain.BudgetWindowCalendarMonth}
	stale.Name, stale.Enabled, stale.UpdatedAt = "renamed", false, time.Now().UTC().Truncate(time.Microsecond)
	stale.Budget = monthly
	stored, err := r.UpdateBudget(ctx, stale)
	require.NoError(t, err)
	require.Equal(t, monthly, stored.Budget)
	require.Equal(t, rotated.KeyHash, stored.KeyHash, "a concurrent rotation is neither undone nor hidden")
	require.NotEqual(t, previousHash, stored.KeyHash)
	require.Equal(t, owned.Name, stored.Name)
	require.True(t, stored.Enabled)
	require.True(t, stored.UpdatedAt.Equal(stale.UpdatedAt))
	_, err = r.FindByAPIKeyHash(ctx, previousHash)
	require.ErrorIs(t, err, domain.ErrNotFound)

	again, err := r.FindByID(ctx, owned.ID)
	require.NoError(t, err)
	_, err = again.RotateAPIKey(time.Now())
	require.NoError(t, err)
	again.Budget = nil
	require.NoError(t, r.Update(ctx, again))
	afterRotate, err := r.FindByID(ctx, owned.ID)
	require.NoError(t, err)
	require.Equal(t, monthly, afterRotate.Budget, "a rotation keeps the budget")

	afterRotate.Budget = nil
	cleared, err := r.UpdateBudget(ctx, afterRotate)
	require.NoError(t, err)
	require.Nil(t, cleared.Budget)
	reread, err := r.FindByID(ctx, owned.ID)
	require.NoError(t, err)
	require.Nil(t, reread.Budget)

	foreign := *reread
	foreign.GatewayID = otherGW
	_, err = r.UpdateBudget(ctx, &foreign)
	require.ErrorIs(t, err, domain.ErrNotFound)
	missing := *reread
	missing.ID = ids.New[ids.AuthKind]()
	_, err = r.UpdateBudget(ctx, &missing)
	require.ErrorIs(t, err, domain.ErrNotFound)
}

func TestRepository_RotateKeyOnlyWinsAgainstTheSecretItRead(t *testing.T) {
	r, gw := setupRepo(t)
	ctx := context.Background()
	gwID, otherGW := seedGateway(t, gw, "rotate-cas"), seedGateway(t, gw, "rotate-cas-other")
	owned := ownedAuth(t, gwID, "alice")
	owned.Budget = &domain.KeyBudget{Max: 50, Unit: domain.BudgetUnitDollars, TimeWindow: domain.BudgetWindowCalendarMonth}
	require.NoError(t, r.Save(ctx, owned))

	first, err := r.FindByID(ctx, owned.ID)
	require.NoError(t, err)
	second, err := r.FindByID(ctx, owned.ID)
	require.NoError(t, err)
	firstPrevious, err := first.RotateAPIKey(time.Now())
	require.NoError(t, err)
	secondPrevious, err := second.RotateAPIKey(time.Now())
	require.NoError(t, err)

	require.NoError(t, r.RotateKey(ctx, first, firstPrevious))
	require.ErrorIs(t, r.RotateKey(ctx, second, secondPrevious), domain.ErrRotatedConcurrently, "the second rotation read a secret that is gone")

	stored, err := r.FindByID(ctx, owned.ID)
	require.NoError(t, err)
	require.Equal(t, first.KeyHash, stored.KeyHash, "the first rotation's secret stands")
	require.Equal(t, owned.Budget, stored.Budget, "a rotation keeps the budget")
	_, err = r.FindByAPIKeyHash(ctx, second.KeyHash)
	require.ErrorIs(t, err, domain.ErrNotFound)

	foreign := *stored
	foreign.GatewayID = otherGW
	require.ErrorIs(t, r.RotateKey(ctx, &foreign, stored.KeyHash), domain.ErrNotFound)
	missing := *stored
	missing.ID = ids.New[ids.AuthKind]()
	require.ErrorIs(t, r.RotateKey(ctx, &missing, stored.KeyHash), domain.ErrNotFound)
}
