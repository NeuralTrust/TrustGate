//go:build functional

package auth_test

import (
	"context"
	"errors"
	"os"
	"sort"
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
)

func setupRepo(t *testing.T) (*repo.Repository, *gatewayrepo.Repository) {
	t.Helper()
	auths, gateways, _ := setupRepoWithPool(t)
	return auths, gateways
}

func setupRepoWithPool(t *testing.T) (*repo.Repository, *gatewayrepo.Repository, *pgxpool.Pool) {
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
	return repo.NewRepository(conn, appender), gatewayrepo.NewRepository(conn, appender), pool
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
	a, err := domain.NewAPIKeyAuth(gwID, name, true)
	if err != nil {
		t.Fatalf("auth domain.NewAPIKeyAuth: %v", err)
	}
	return a
}

func validIDPAuth(t *testing.T, gwID ids.GatewayID, name string, enabled bool) *domain.Auth {
	t.Helper()
	a, err := domain.NewAuth(gwID, name, domain.TypeOAuth2, enabled, domain.Config{OAuth2: &domain.OAuth2Config{
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

// saveLegacyOIDCAuth plants a row in the shape the unification migration
// replaced: type "oidc" with the payload under the oidc key. The domain can no
// longer build one, so a native row is saved and then rewritten in place. The
// constraint comes back NOT VALID to keep rejecting new legacy writes while
// leaving this row, which is what a restore or a rolled-back migration leaves
// behind.
func saveLegacyOIDCAuth(
	t *testing.T,
	r *repo.Repository,
	pool *pgxpool.Pool,
	gwID ids.GatewayID,
	name string,
) *domain.Auth {
	t.Helper()
	ctx := context.Background()
	a := validIDPAuth(t, gwID, name, true)
	if err := r.Save(ctx, a); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := pool.Exec(ctx, `ALTER TABLE auths DROP CONSTRAINT IF EXISTS auths_type_check`); err != nil {
		t.Fatalf("relax the auth type constraint: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		UPDATE auths
		SET type = 'oidc',
		    config = jsonb_build_object('oidc', config -> 'oauth2')
		WHERE id = $1`, a.ID,
	); err != nil {
		t.Fatalf("rewrite the row into the legacy shape: %v", err)
	}
	if _, err := pool.Exec(ctx, `
		ALTER TABLE auths
		ADD CONSTRAINT auths_type_check CHECK (type IN ('api_key','oauth2','mtls')) NOT VALID`,
	); err != nil {
		t.Fatalf("restore the auth type constraint: %v", err)
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

func TestRepository_LegacyOIDCRowReadsBackAsOAuth2(t *testing.T) {
	r, gw, pool := setupRepoWithPool(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-legacy-oidc")

	stored := saveLegacyOIDCAuth(t, r, pool, gwID, "legacy-idp")

	got, err := r.FindByID(ctx, stored.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Type != domain.TypeOAuth2 {
		t.Fatalf("type = %q, want %q", got.Type, domain.TypeOAuth2)
	}
	if got.Config.OAuth2 == nil {
		t.Fatal("config.oauth2 is nil, want the legacy payload normalized onto it")
	}
	if got.Config.OAuth2.JWKSURL != stored.Config.OAuth2.JWKSURL {
		t.Fatalf("jwks url = %q, want %q", got.Config.OAuth2.JWKSURL, stored.Config.OAuth2.JWKSURL)
	}
	if len(got.Config.OAuth2.Algorithms) != 1 || got.Config.OAuth2.Algorithms[0] != "RS256" {
		t.Fatalf("allowed algorithms = %v", got.Config.OAuth2.Algorithms)
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

func TestRepository_List_TypeFilterMatchesEveryStoredRepresentation(t *testing.T) {
	r, gw, pool := setupRepoWithPool(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "agw-stored-types")

	legacy := saveLegacyOIDCAuth(t, r, pool, gwID, "legacy-idp")
	for _, a := range []*domain.Auth{validIDPAuth(t, gwID, "native-idp", true), validAuth(t, gwID, "api-key")} {
		if err := r.Save(ctx, a); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}

	var storedType string
	if err := pool.QueryRow(ctx, `SELECT type FROM auths WHERE id = $1`, legacy.ID).Scan(&storedType); err != nil {
		t.Fatalf("read stored type: %v", err)
	}
	if storedType != string(domain.TypeOIDC) {
		t.Fatalf("stored type = %q, want %q; the fixture is not a pre-migration row",
			storedType, domain.TypeOIDC)
	}

	for _, filterType := range []domain.Type{domain.TypeOAuth2, domain.TypeOIDC} {
		t.Run(string(filterType), func(t *testing.T) {
			items, total, err := r.List(ctx, domain.ListFilter{
				GatewayID: gwID,
				Type:      filterType,
				Page:      listing.Page{Number: 1, Size: 10},
			})
			if err != nil {
				t.Fatalf("List: %v", err)
			}
			if total != len(items) {
				t.Fatalf("total = %d but page holds %d items", total, len(items))
			}
			names := make([]string, 0, len(items))
			for _, a := range items {
				names = append(names, a.Name)
				if a.Type != domain.TypeOAuth2 {
					t.Fatalf("item %q has type %q, want it normalized to %q",
						a.Name, a.Type, domain.TypeOAuth2)
				}
			}
			sort.Strings(names)
			if len(names) != 2 || names[0] != "legacy-idp" || names[1] != "native-idp" {
				t.Fatalf("page = %v, want both the legacy and the native identity provider", names)
			}
		})
	}
}
