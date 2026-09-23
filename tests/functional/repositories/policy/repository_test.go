//go:build functional

package policy_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"reflect"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	_ "github.com/NeuralTrust/TrustGate/pkg/infra/database/migrations"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/openaimoderation"
	consumerrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/consumer"
	gatewayrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/gateway"
	outboxrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/outbox"
	repo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/policy"
	registryrepo "github.com/NeuralTrust/TrustGate/pkg/infra/repository/registry"
	"github.com/jackc/pgx/v5/pgxpool"
)

// credentialSlug and credentialPath name the one real plugin these tests use
// to exercise RUN-1646's leaf-level settings encryption: openai_moderation
// declares "api_key" as its only credential path (see
// pkg/infra/plugins/openaimoderation/plugin.go), and its constructor takes no
// live dependency these tests need to satisfy (the plugin is never Executed
// here, only registered so PluginCredentialPaths can resolve its slug).
const (
	credentialSlug           = openaimoderation.PluginName
	credentialPath           = "api_key"
	credentialNonSecretField = "model"
)

func newTestCipher(t *testing.T) vaultdomain.Encrypter {
	t.Helper()
	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	return cipher
}

// newTestPluginRegistry registers exactly the one plugin these tests need
// (see credentialSlug) rather than the full production catalog
// (pkg/container/modules.Plugins), keeping this package's dependency surface
// to what it actually exercises.
func newTestPluginRegistry(t *testing.T) appplugins.Registry {
	t.Helper()
	reg := appplugins.NewRegistry()
	plugin := openaimoderation.New(nil, "", time.Second, slog.Default())
	if err := reg.Register(plugin); err != nil {
		t.Fatalf("register %s: %v", credentialSlug, err)
	}
	return reg
}

func newRegistryRepo(conn *database.Connection) *registryrepo.Repository {
	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		panic(err)
	}
	return registryrepo.NewRepository(conn, cipher, outboxrepo.NewRepository(conn))
}

func setupRepo(t *testing.T) (*repo.Repository, *gatewayrepo.Repository, *database.Connection) {
	t.Helper()
	dsn := os.Getenv("PG_TEST_URL")
	if dsn == "" {
		t.Skip("PG_TEST_URL not set; skipping policy repository integration test")
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
		_, _ = pool.Exec(context.Background(), "TRUNCATE TABLE consumer_policy, policies, consumers, registries, gateways CASCADE")
		pool.Close()
	})

	appender := outboxrepo.NewRepository(conn)
	r := repo.NewRepository(conn, appender, newTestCipher(t), newTestPluginRegistry(t))
	return r, gatewayrepo.NewRepository(conn, appender), conn
}

// credentialPolicy builds a policy whose slug declares a credential path
// (see credentialSlug), with secret as the credential value and a sibling
// plain field (credentialNonSecretField) that must stay queryable as normal
// JSON after RUN-1646 — proving the design only touches declared leaves, not
// the whole settings blob.
func credentialPolicy(t *testing.T, gwID ids.GatewayID, name, secretValue string) *domain.Policy {
	t.Helper()
	p, err := domain.NewPolicy(gwID, name, credentialSlug, true, 0, false,
		map[string]any{credentialPath: secretValue, credentialNonSecretField: "omni-moderation-latest"},
		[]domain.Stage{domain.StagePreRequest}, "", domain.ModeEnforce, nil)
	if err != nil {
		t.Fatalf("policy domain.NewPolicy: %v", err)
	}
	return p
}

// rawSettingsField reads settings->>field directly with SQL, bypassing the
// repository entirely — this is what proves a credential leaf is genuinely
// unreadable in the raw column rather than merely masked by the Go layer.
func rawSettingsField(t *testing.T, conn *database.Connection, id ids.PolicyID, field string) string {
	t.Helper()
	var val *string
	if err := conn.Pool.QueryRow(context.Background(),
		"SELECT settings->>$2 FROM policies WHERE id = $1", id, field,
	).Scan(&val); err != nil {
		t.Fatalf("read raw settings.%s: %v", field, err)
	}
	if val == nil {
		return ""
	}
	return *val
}

func seedConsumer(t *testing.T, conn *database.Connection, gwID ids.GatewayID, name string) ids.ConsumerID {
	t.Helper()
	ctx := context.Background()
	reg, err := registrydomain.NewLLMRegistry(gwID, name+"-reg", "", &registrydomain.LLMTarget{
		Provider: "openai",
		Auth:     registrydomain.NewAPIKeyAuth("sk-test"),
	})
	if err != nil {
		t.Fatalf("registry domain.NewLLMRegistry: %v", err)
	}
	if err := newRegistryRepo(conn).Save(ctx, reg); err != nil {
		t.Fatalf("registry Save: %v", err)
	}
	cons, err := consumerdomain.New(consumerdomain.CreateParams{
		GatewayID:   gwID,
		Name:        name,
		Type:        consumerdomain.TypeLLM,
		RegistryIDs: []ids.RegistryID{reg.ID},
	})
	if err != nil {
		t.Fatalf("consumer domain.New: %v", err)
	}
	if err := consumerrepo.NewRepository(conn, outboxrepo.NewRepository(conn)).Save(ctx, cons); err != nil {
		t.Fatalf("consumer Save: %v", err)
	}
	return cons.ID
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

func validPolicy(t *testing.T, gwID ids.GatewayID, name string) *domain.Policy {
	t.Helper()
	p, err := domain.NewPolicy(gwID, name, "rate_limiter", true, 0, false,
		map[string]any{"limit": 100}, []domain.Stage{domain.StagePreRequest}, "round-trip description", domain.ModeEnforce, nil)
	if err != nil {
		t.Fatalf("policy domain.NewPolicy: %v", err)
	}
	return p
}

func scopedPolicy(t *testing.T, gwID ids.GatewayID, name string, scope *domain.MCPScope) *domain.Policy {
	t.Helper()
	p, err := domain.NewPolicy(gwID, name, "trustguard", true, 0, false,
		nil, []domain.Stage{domain.StagePreRequest}, "", domain.ModeEnforce, scope)
	if err != nil {
		t.Fatalf("policy domain.NewPolicy: %v", err)
	}
	return p
}

func seedMCPRegistry(t *testing.T, conn *database.Connection, gwID ids.GatewayID, name string) ids.RegistryID {
	t.Helper()
	reg, err := registrydomain.NewMCPRegistry(gwID, name, "", &registrydomain.MCPTarget{
		URL: "https://" + name + ".example.com/mcp",
	})
	if err != nil {
		t.Fatalf("registry domain.NewMCPRegistry: %v", err)
	}
	if err := newRegistryRepo(conn).Save(context.Background(), reg); err != nil {
		t.Fatalf("registry Save: %v", err)
	}
	return reg.ID
}

func rawMCPScope(t *testing.T, conn *database.Connection, id ids.PolicyID) (isNull bool, text string) {
	t.Helper()
	if err := conn.Pool.QueryRow(context.Background(),
		"SELECT mcp_scope IS NULL, COALESCE(mcp_scope::text, '') FROM policies WHERE id = $1", id,
	).Scan(&isNull, &text); err != nil {
		t.Fatalf("read raw mcp_scope: %v", err)
	}
	return isNull, text
}

func policyIDs(items []*domain.Policy) []ids.PolicyID {
	out := make([]ids.PolicyID, 0, len(items))
	for _, p := range items {
		out = append(out, p.ID)
	}
	return out
}

func TestRepository_SaveAndFindByID(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw")

	p := validPolicy(t, gwID, "default")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.ID != p.ID || got.GatewayID != gwID || got.Name != "default" {
		t.Fatalf("FindByID returned %+v", got)
	}
	if got.Slug != "rate_limiter" {
		t.Fatalf("Slug round-trip lost data: %+v", got)
	}
	if got.Description != "round-trip description" {
		t.Fatalf("Description round-trip lost data: %+v", got)
	}
	if len(got.Stages) != 1 || got.Stages[0] != domain.StagePreRequest {
		t.Fatalf("Stages round-trip lost data: %+v", got.Stages)
	}
	if got.Mode != domain.ModeEnforce {
		t.Fatalf("Mode round-trip lost data: %+v", got.Mode)
	}
	if got.Settings["limit"] != float64(100) {
		t.Fatalf("Settings round-trip lost data: %+v", got.Settings)
	}
}

func TestRepository_SaveAndFindByID_EmptySettings(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-empty")

	p, err := domain.NewPolicy(gwID, "empty", "rate_limiter", true, 0, false, nil, nil, "", domain.ModeEnforce, nil)
	if err != nil {
		t.Fatalf("domain.NewPolicy: %v", err)
	}
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.Settings) != 0 {
		t.Fatalf("Settings len = %d, want 0", len(got.Settings))
	}
	if len(got.Stages) != 0 {
		t.Fatalf("Stages len = %d, want 0", len(got.Stages))
	}
}

func TestRepository_FindByID_NotFound(t *testing.T) {
	r, _, _ := setupRepo(t)
	_, err := r.FindByID(context.Background(), ids.New[ids.PolicyKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
	if !errors.Is(err, commonerrors.ErrNotFound) {
		t.Fatalf("err = %v, want it to wrap commonerrors.ErrNotFound", err)
	}
}

func TestRepository_Save_DuplicateNameForSameGateway(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-dup")

	p1 := validPolicy(t, gwID, "dupe")
	if err := r.Save(ctx, p1); err != nil {
		t.Fatalf("first Save: %v", err)
	}
	p2 := validPolicy(t, gwID, "dupe")
	err := r.Save(ctx, p2)
	if !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("err = %v, want ErrAlreadyExists", err)
	}
}

func TestRepository_Save_InvalidGatewayID(t *testing.T) {
	r, _, _ := setupRepo(t)
	ctx := context.Background()
	orphan := ids.New[ids.GatewayKind]()
	p := validPolicy(t, orphan, "orphan")
	err := r.Save(ctx, p)
	if !errors.Is(err, domain.ErrInvalidGatewayID) {
		t.Fatalf("err = %v, want ErrInvalidGatewayID", err)
	}
}

func TestRepository_Update(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-upd")

	p := validPolicy(t, gwID, "alpha")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	p.Name = "alpha-renamed"
	p.Slug = "rate_limiter"
	p.Enabled = false
	p.Stages = []domain.Stage{domain.StagePostResponse}
	p.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, p, true); err != nil {
		t.Fatalf("Update: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after update: %v", err)
	}
	if got.Name != "alpha-renamed" {
		t.Fatalf("Name = %q, want alpha-renamed", got.Name)
	}
	if got.Slug != "rate_limiter" || got.Enabled {
		t.Fatalf("update not persisted: %+v", got)
	}
	if len(got.Stages) != 1 || got.Stages[0] != domain.StagePostResponse {
		t.Fatalf("Stages not persisted: %+v", got.Stages)
	}
}

func TestRepository_Update_NotFound(t *testing.T) {
	r, gw, _ := setupRepo(t)
	gwID := seedGateway(t, gw, "pgw-upd2")
	p := validPolicy(t, gwID, "ghost")
	err := r.Update(context.Background(), p, true)
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-del")

	p := validPolicy(t, gwID, "victim")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := r.Delete(ctx, gwID, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := r.FindByID(ctx, p.ID); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_Delete_NotFound(t *testing.T) {
	r, _, _ := setupRepo(t)
	err := r.Delete(context.Background(), ids.New[ids.GatewayKind](), ids.New[ids.PolicyKind]())
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("err = %v, want ErrNotFound", err)
	}
}

func TestRepository_List_FilterByGatewayAndName(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gw1 := seedGateway(t, gw, "pgw-l1")
	gw2 := seedGateway(t, gw, "pgw-l2")

	mustSave := func(p *domain.Policy) {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	mustSave(validPolicy(t, gw1, "openai-prod"))
	mustSave(validPolicy(t, gw1, "openai-staging"))
	mustSave(validPolicy(t, gw2, "anthropic-prod"))

	items, total, err := r.List(ctx, domain.ListFilter{GatewayID: gw1, Page: listing.Page{Number: 1, Size: 10}})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("List(gw1) total=%d len=%d, want 2/2", total, len(items))
	}

	items, total, err = r.List(ctx, domain.ListFilter{Search: "anthropic", Page: listing.Page{Number: 1, Size: 10}})
	if err != nil {
		t.Fatalf("List name: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Name != "anthropic-prod" {
		t.Fatalf("List(name) returned %+v", items)
	}

	items, total, err = r.List(ctx, domain.ListFilter{Page: listing.Page{Number: 1, Size: 10}})
	if err != nil {
		t.Fatalf("List all: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("List all total=%d len=%d, want 3/3", total, len(items))
	}
}

func TestRepository_List_RestrictToSlugs(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-slug")

	mustSave := func(p *domain.Policy) {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save: %v", err)
		}
	}
	mustSave(validPolicy(t, gwID, "rate-one"))
	p2, err := domain.NewPolicy(gwID, "size-one", "request_size_limiter", true, 0, false,
		map[string]any{"allowed_payload_size": 10, "size_unit": "megabytes"}, []domain.Stage{domain.StagePreRequest}, "", domain.ModeEnforce, nil)
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	mustSave(p2)

	items, total, err := r.List(ctx, domain.ListFilter{
		GatewayID:       gwID,
		RestrictToSlugs: true,
		Slugs:           []string{"rate_limiter"},
		Page:            listing.Page{Number: 1, Size: 10},
	})
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].Slug != "rate_limiter" {
		t.Fatalf("List(slug) total=%d items=%+v", total, items)
	}

	items, total, err = r.List(ctx, domain.ListFilter{
		GatewayID:       gwID,
		RestrictToSlugs: true,
		Slugs:           []string{},
		Page:            listing.Page{Number: 1, Size: 10},
	})
	if err != nil {
		t.Fatalf("List empty slugs: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("List(empty restrict) total=%d len=%d", total, len(items))
	}
}

func TestRepository_GlobalFlag_RoundTripAndListByGateway(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-global")

	global := validPolicy(t, gwID, "global-pol")
	if err := r.Save(ctx, global); err != nil {
		t.Fatalf("Save global: %v", err)
	}
	if err := r.SetGlobal(ctx, gwID, global.ID, true); err != nil {
		t.Fatalf("SetGlobal: %v", err)
	}

	scoped := validPolicy(t, gwID, "scoped-pol")
	if err := r.Save(ctx, scoped); err != nil {
		t.Fatalf("Save scoped: %v", err)
	}

	got, err := r.FindByID(ctx, global.ID)
	if err != nil {
		t.Fatalf("FindByID global: %v", err)
	}
	if !got.IsGlobal() {
		t.Fatal("policy promoted via SetGlobal should report global")
	}

	all, err := r.ListByGateway(ctx, gwID)
	if err != nil {
		t.Fatalf("ListByGateway: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("ListByGateway len = %d, want 2", len(all))
	}
	var globals, scopedCount int
	for _, p := range all {
		if p.IsGlobal() {
			globals++
		} else {
			scopedCount++
		}
	}
	if globals != 1 || scopedCount != 1 {
		t.Fatalf("expected 1 global + 1 scoped, got %d/%d", globals, scopedCount)
	}
}

func TestRepository_ConsumerPolicyJunction_AttachDetachRoundTrip(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-junction")
	c1 := seedConsumer(t, conn, gwID, "junction-a")
	c2 := seedConsumer(t, conn, gwID, "junction-b")
	consumers := consumerrepo.NewRepository(conn, outboxrepo.NewRepository(conn))

	p := validPolicy(t, gwID, "linked")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Junctions are written exclusively through the consumer repository.
	if err := consumers.AttachPolicy(ctx, c1, p.ID); err != nil {
		t.Fatalf("AttachPolicy c1: %v", err)
	}
	if err := consumers.AttachPolicy(ctx, c2, p.ID); err != nil {
		t.Fatalf("AttachPolicy c2: %v", err)
	}
	// Idempotent re-attach must not error.
	if err := consumers.AttachPolicy(ctx, c1, p.ID); err != nil {
		t.Fatalf("AttachPolicy c1 (idempotent): %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if len(got.ConsumerIDs) != 2 {
		t.Fatalf("ConsumerIDs projection lost data: %+v", got.ConsumerIDs)
	}

	if err := consumers.DetachPolicy(ctx, c1, p.ID); err != nil {
		t.Fatalf("DetachPolicy c1: %v", err)
	}
	got, err = r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after detach: %v", err)
	}
	if len(got.ConsumerIDs) != 1 || got.ConsumerIDs[0] != c2 {
		t.Fatalf("detach did not leave exactly c2: %+v", got.ConsumerIDs)
	}
}

func TestRepository_DeletePolicy_CascadesJunction(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-cascade")
	c1 := seedConsumer(t, conn, gwID, "cascade-a")
	consumers := consumerrepo.NewRepository(conn, outboxrepo.NewRepository(conn))

	p := validPolicy(t, gwID, "cascade")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if err := consumers.AttachPolicy(ctx, c1, p.ID); err != nil {
		t.Fatalf("AttachPolicy: %v", err)
	}
	if err := r.Delete(ctx, gwID, p.ID); err != nil {
		t.Fatalf("Delete: %v", err)
	}

	var count int
	if err := conn.Pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM consumer_policy WHERE policy_id = $1", p.ID).Scan(&count); err != nil {
		t.Fatalf("count junction: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected junction rows to be cascaded on policy delete, got %d", count)
	}
}

func TestRepository_MCPScope_RoundTrip(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope")
	snowflake := seedMCPRegistry(t, conn, gwID, "scope-snowflake")
	jira := seedMCPRegistry(t, conn, gwID, "scope-jira")

	full := &domain.MCPScope{
		RegistryIDs:  []ids.RegistryID{jira},
		Tools:        []domain.MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}},
		Groups:       []string{"Finanzas"},
		ExceptGroups: []string{"Contractors"},
	}
	unscoped := scopedPolicy(t, gwID, "unscoped", nil)
	pruned := scopedPolicy(t, gwID, "pruned", &domain.MCPScope{})
	scoped := scopedPolicy(t, gwID, "scoped", full)
	for _, p := range []*domain.Policy{unscoped, pruned, scoped} {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", p.Name, err)
		}
	}

	got, err := r.FindByID(ctx, unscoped.ID)
	if err != nil {
		t.Fatalf("FindByID unscoped: %v", err)
	}
	if got.MCPScope != nil {
		t.Fatalf("nil scope came back as %+v, want nil", got.MCPScope)
	}
	if isNull, _ := rawMCPScope(t, conn, unscoped.ID); !isNull {
		t.Fatal("nil scope must be stored as SQL NULL")
	}

	got, err = r.FindByID(ctx, pruned.ID)
	if err != nil {
		t.Fatalf("FindByID pruned: %v", err)
	}
	if got.MCPScope == nil || !got.MCPScope.IsEmpty() {
		t.Fatalf("empty scope came back as %+v, want &MCPScope{}", got.MCPScope)
	}
	if isNull, text := rawMCPScope(t, conn, pruned.ID); isNull || text != "{}" {
		t.Fatalf("empty scope stored as (null=%v, %q), want '{}'", isNull, text)
	}

	got, err = r.FindByID(ctx, scoped.ID)
	if err != nil {
		t.Fatalf("FindByID scoped: %v", err)
	}
	if !reflect.DeepEqual(got.MCPScope, full) {
		t.Fatalf("scope round-trip lost data:\n got %+v\nwant %+v", got.MCPScope, full)
	}

	byIDs, err := r.FindByIDs(ctx, gwID, []ids.PolicyID{scoped.ID, pruned.ID})
	if err != nil {
		t.Fatalf("FindByIDs: %v", err)
	}
	if len(byIDs) != 2 {
		t.Fatalf("FindByIDs len = %d, want 2", len(byIDs))
	}
	for _, p := range byIDs {
		if p.ID == scoped.ID && !reflect.DeepEqual(p.MCPScope, full) {
			t.Fatalf("FindByIDs lost scope: %+v", p.MCPScope)
		}
		if p.ID == pruned.ID && (p.MCPScope == nil || !p.MCPScope.IsEmpty()) {
			t.Fatalf("FindByIDs turned {} into %+v", p.MCPScope)
		}
	}
	all, err := r.ListByGateway(ctx, gwID)
	if err != nil {
		t.Fatalf("ListByGateway: %v", err)
	}
	if len(all) != 3 {
		t.Fatalf("ListByGateway len = %d, want 3", len(all))
	}
}

func TestRepository_MCPScope_UpdateTransitions(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope-upd")
	snowflake := seedMCPRegistry(t, conn, gwID, "upd-snowflake")

	p := scopedPolicy(t, gwID, "transitions", nil)
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	p.MCPScope = &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}}
	p.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, p, true); err != nil {
		t.Fatalf("Update nil -> scope: %v", err)
	}
	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.MCPScope == nil || len(got.MCPScope.RegistryIDs) != 1 || got.MCPScope.RegistryIDs[0] != snowflake {
		t.Fatalf("scope not persisted on update: %+v", got.MCPScope)
	}

	p.MCPScope = &domain.MCPScope{}
	if err := r.Update(ctx, p, true); err != nil {
		t.Fatalf("Update scope -> {}: %v", err)
	}
	if isNull, text := rawMCPScope(t, conn, p.ID); isNull || text != "{}" {
		t.Fatalf("empty scope stored as (null=%v, %q), want '{}'", isNull, text)
	}

	p.MCPScope = nil
	if err := r.Update(ctx, p, true); err != nil {
		t.Fatalf("Update {} -> nil: %v", err)
	}
	if isNull, _ := rawMCPScope(t, conn, p.ID); !isNull {
		t.Fatal("clearing the scope must write SQL NULL")
	}
	got, err = r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after clear: %v", err)
	}
	if got.MCPScope != nil {
		t.Fatalf("cleared scope came back as %+v, want nil", got.MCPScope)
	}
}

// An update that did not carry an mcp_scope must leave the column alone. The
// caller read the policy before a registry delete pruned it; writing the value
// it read back would resurrect a registry that no longer exists, and the prune
// cannot defend itself because the caller never took its row lock.
func TestRepository_Update_WithoutScopeWriteKeepsTheStoredScope(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope-nowrite")
	snowflake := seedMCPRegistry(t, conn, gwID, "nowrite-snowflake")

	p := scopedPolicy(t, gwID, "no-write", &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}})
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Somebody else prunes the scope to {} while this caller holds a stale read.
	stale := *p
	if _, err := conn.Pool.Exec(ctx, `UPDATE policies SET mcp_scope = '{}' WHERE id = $1`, p.ID); err != nil {
		t.Fatalf("prune: %v", err)
	}

	stale.Name = "renamed"
	stale.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, &stale, false); err != nil {
		t.Fatalf("Update without scope write: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Name != "renamed" {
		t.Fatalf("Name = %q, want the update to have landed", got.Name)
	}
	if got.MCPScope == nil || !got.MCPScope.IsEmpty() {
		t.Fatalf("MCPScope = %+v, want the pruned {} to have survived", got.MCPScope)
	}
	if isNull, text := rawMCPScope(t, conn, p.ID); isNull || text != "{}" {
		t.Fatalf("stored scope = (null=%v, %q), want '{}'", isNull, text)
	}
}

func TestRepository_List_FilterByRegistryID(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope-list")
	snowflake := seedMCPRegistry(t, conn, gwID, "list-snowflake")
	jira := seedMCPRegistry(t, conn, gwID, "list-jira")

	byRegistry := scopedPolicy(t, gwID, "by-registry", &domain.MCPScope{RegistryIDs: []ids.RegistryID{snowflake}})
	byTool := scopedPolicy(t, gwID, "by-tool", &domain.MCPScope{Tools: []domain.MCPToolRef{{RegistryID: snowflake, Tool: "run_query"}}})
	other := scopedPolicy(t, gwID, "other-registry", &domain.MCPScope{RegistryIDs: []ids.RegistryID{jira}})
	pruned := scopedPolicy(t, gwID, "pruned", &domain.MCPScope{})
	unscoped := scopedPolicy(t, gwID, "unscoped", nil)
	for _, p := range []*domain.Policy{byRegistry, byTool, other, pruned, unscoped} {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", p.Name, err)
		}
	}

	page := listing.Page{Number: 1, Size: 10}
	items, total, err := r.List(ctx, domain.ListFilter{GatewayID: gwID, RegistryID: &snowflake, Page: page})
	if err != nil {
		t.Fatalf("List registry_id=snowflake: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("List(snowflake) total=%d len=%d, want 2/2: %v", total, len(items), policyIDs(items))
	}
	for _, p := range items {
		if p.ID != byRegistry.ID && p.ID != byTool.ID {
			t.Fatalf("List(snowflake) returned unexpected policy %s (%s)", p.ID, p.Name)
		}
	}

	items, total, err = r.List(ctx, domain.ListFilter{GatewayID: gwID, RegistryID: &jira, Page: page})
	if err != nil {
		t.Fatalf("List registry_id=jira: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != other.ID {
		t.Fatalf("List(jira) total=%d items=%v, want only %s", total, policyIDs(items), other.ID)
	}

	unknown := ids.New[ids.RegistryKind]()
	items, total, err = r.List(ctx, domain.ListFilter{GatewayID: gwID, RegistryID: &unknown, Page: page})
	if err != nil {
		t.Fatalf("List registry_id=unknown: %v", err)
	}
	if total != 0 || len(items) != 0 {
		t.Fatalf("List(unknown) total=%d len=%d, want 0/0", total, len(items))
	}

	items, total, err = r.List(ctx, domain.ListFilter{GatewayID: gwID, Page: page})
	if err != nil {
		t.Fatalf("List without registry_id: %v", err)
	}
	if total != 5 || len(items) != 5 {
		t.Fatalf("List(all) total=%d len=%d, want 5/5", total, len(items))
	}
}

func TestRepository_DeleteRegistry_PrunesMCPScopeInSameTx(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-scope-prune")
	otherGW := seedGateway(t, gw, "pgw-scope-prune-other")
	keeper := seedMCPRegistry(t, conn, gwID, "prune-keeper")
	victim := seedMCPRegistry(t, conn, gwID, "prune-victim")

	several := scopedPolicy(t, gwID, "several-registries", &domain.MCPScope{
		RegistryIDs: []ids.RegistryID{keeper, victim},
		Groups:      []string{"Finanzas"},
	})
	only := scopedPolicy(t, gwID, "only-victim-tool", &domain.MCPScope{
		Tools: []domain.MCPToolRef{{RegistryID: victim, Tool: "run_query"}},
	})
	untouched := scopedPolicy(t, gwID, "keeper-only", &domain.MCPScope{RegistryIDs: []ids.RegistryID{keeper}})
	unscoped := scopedPolicy(t, gwID, "unscoped", nil)
	foreign := scopedPolicy(t, otherGW, "foreign-reference", &domain.MCPScope{RegistryIDs: []ids.RegistryID{victim}})
	for _, p := range []*domain.Policy{several, only, untouched, unscoped, foreign} {
		if err := r.Save(ctx, p); err != nil {
			t.Fatalf("Save %s: %v", p.Name, err)
		}
	}
	before, err := r.FindByID(ctx, untouched.ID)
	if err != nil {
		t.Fatalf("FindByID untouched: %v", err)
	}

	cipher, err := crypto.NewCipher("functional-test-secret-0123456789abcdef")
	if err != nil {
		t.Fatalf("new cipher: %v", err)
	}
	registries := registryrepo.NewRepository(conn, cipher, outboxrepo.NewRepository(conn),
		registryrepo.WithDeleteHook(r.PruneRegistryReferencesTx))
	report, err := registries.Delete(ctx, gwID, victim)
	if err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if report.Empty() || len(report.Policies) != 2 {
		t.Fatalf("report = %+v, want exactly the two pruned policies", report)
	}
	emptied := map[ids.PolicyID]bool{}
	for _, prune := range report.Policies {
		emptied[prune.PolicyID] = prune.Emptied
	}
	if got, ok := emptied[several.ID]; !ok || got {
		t.Fatalf("report for %s = (present=%v, emptied=%v), want present and not emptied", several.Name, ok, got)
	}
	if got, ok := emptied[only.ID]; !ok || !got {
		t.Fatalf("report for %s = (present=%v, emptied=%v), want present and emptied", only.Name, ok, got)
	}

	got, err := r.FindByID(ctx, several.ID)
	if err != nil {
		t.Fatalf("FindByID several: %v", err)
	}
	if got.MCPScope == nil || len(got.MCPScope.RegistryIDs) != 1 || got.MCPScope.RegistryIDs[0] != keeper {
		t.Fatalf("several-registries scope = %+v, want only %s", got.MCPScope, keeper)
	}
	if len(got.MCPScope.Groups) != 1 || got.MCPScope.Groups[0] != "Finanzas" {
		t.Fatalf("prune must keep the principal dimension: %+v", got.MCPScope)
	}
	if !got.UpdatedAt.After(several.UpdatedAt) {
		t.Fatalf("updated_at not bumped: %s <= %s", got.UpdatedAt, several.UpdatedAt)
	}

	got, err = r.FindByID(ctx, only.ID)
	if err != nil {
		t.Fatalf("FindByID only: %v", err)
	}
	if got.MCPScope == nil || !got.MCPScope.IsEmpty() {
		t.Fatalf("only-victim-tool scope = %+v, want {}", got.MCPScope)
	}
	if isNull, text := rawMCPScope(t, conn, only.ID); isNull || text != "{}" {
		t.Fatalf("pruned scope stored as (null=%v, %q), want '{}' and never NULL", isNull, text)
	}
	if ok, _ := got.MCPScope.Matches(domain.MCPTarget{RegistryID: keeper, Tool: "run_query"}, domain.MCPCaller{}); ok {
		t.Fatal("a pruned {} scope must not match any target")
	}

	got, err = r.FindByID(ctx, untouched.ID)
	if err != nil {
		t.Fatalf("FindByID untouched: %v", err)
	}
	if !reflect.DeepEqual(got.MCPScope, before.MCPScope) || !got.UpdatedAt.Equal(before.UpdatedAt) {
		t.Fatalf("keeper-only policy was rewritten: %+v (updated_at %s -> %s)", got.MCPScope, before.UpdatedAt, got.UpdatedAt)
	}
	if isNull, _ := rawMCPScope(t, conn, unscoped.ID); !isNull {
		t.Fatal("an unscoped policy must stay NULL after a prune")
	}
	got, err = r.FindByID(ctx, foreign.ID)
	if err != nil {
		t.Fatalf("FindByID foreign: %v", err)
	}
	if got.MCPScope == nil || len(got.MCPScope.RegistryIDs) != 1 || got.MCPScope.RegistryIDs[0] != victim {
		t.Fatalf("prune crossed the gateway boundary: %+v", got.MCPScope)
	}
	if _, err := newRegistryRepo(conn).FindByID(ctx, victim); !errors.Is(err, registrydomain.ErrNotFound) {
		t.Fatalf("registry FindByID after delete err = %v, want ErrNotFound", err)
	}
}

// --- RUN-1646: leaf-level credential encryption at rest -------------------

func TestRepository_CredentialSettings_RawColumnDoesNotHoldThePlaintext(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-cred-raw")

	const secretValue = "sk-real-secret-abcdef1234"
	p := credentialPolicy(t, gwID, "cred-raw", secretValue)
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw := rawSettingsField(t, conn, p.ID, credentialPath)
	if raw == secretValue {
		t.Fatalf("settings->>%q returned the plaintext secret directly from SQL: %q", credentialPath, raw)
	}
	if raw == "" {
		t.Fatal("settings->>credentialPath was empty; expected version-prefixed ciphertext")
	}
}

// This is the test that proves the design choice in the briefing held: a
// non-credential key must stay plain, queryable JSON in the raw column after
// RUN-1646, not folded into an opaque encrypted blob.
func TestRepository_CredentialSettings_NonCredentialFieldStaysPlainJSON(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-cred-plain")

	p := credentialPolicy(t, gwID, "cred-plain", "sk-real-secret-abcdef1234")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	raw := rawSettingsField(t, conn, p.ID, credentialNonSecretField)
	if raw != "omni-moderation-latest" {
		t.Fatalf("settings->>%q = %q, want the plain value directly queryable from SQL", credentialNonSecretField, raw)
	}
}

func TestRepository_CredentialSettings_RoundTrip(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-cred-rt")

	const secretValue = "sk-real-secret-roundtrip-9876"
	p := credentialPolicy(t, gwID, "cred-rt", secretValue)
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Settings[credentialPath] != secretValue {
		t.Fatalf("Settings[%q] = %v, want the original secret back", credentialPath, got.Settings[credentialPath])
	}

	// This is also the "plugin execution path receives the real decrypted
	// secret" guarantee: app/plugins/plan.go hands *domain.Policy.Settings
	// straight to policy.PluginConfig.Settings with no further transform, so
	// whatever scanPolicy put in got.Settings is exactly what a plugin sees.
	if got.Settings[credentialNonSecretField] != "omni-moderation-latest" {
		t.Fatalf("sibling non-secret field lost on round trip: %+v", got.Settings)
	}
}

// Most important test in the set: a row written before RUN-1646 (or before
// the backfill reached it) holds its credential as raw plaintext JSON, with
// no version prefix at all. It must load exactly as it did before, with no
// error and no data loss.
func TestRepository_CredentialSettings_LegacyPlaintextRowStillLoads(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-cred-legacy")

	p := credentialPolicy(t, gwID, "cred-legacy", "placeholder-will-be-overwritten")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Bypass the repository entirely and write raw plaintext JSON directly,
	// simulating a row that predates leaf-level encryption.
	const legacySecret = "sk-legacy-plaintext-value-5555"
	legacyJSON := fmt.Sprintf(`{"api_key":%q,"model":"omni-moderation-latest"}`, legacySecret)
	if _, err := conn.Pool.Exec(ctx, `UPDATE policies SET settings = $1::jsonb WHERE id = $2`, legacyJSON, p.ID); err != nil {
		t.Fatalf("force legacy plaintext row: %v", err)
	}

	// Confirm the raw column really has no version prefix, i.e. this is a
	// faithful simulation of a pre-RUN-1646 row.
	if raw := rawSettingsField(t, conn, p.ID, credentialPath); raw != legacySecret {
		t.Fatalf("test setup broken: raw settings.%s = %q, want the legacy plaintext %q", credentialPath, raw, legacySecret)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID on a legacy plaintext row returned an error, want the tolerant read to pass it through: %v", err)
	}
	if got.Settings[credentialPath] != legacySecret {
		t.Fatalf("Settings[%q] = %v, want the legacy plaintext returned untouched", credentialPath, got.Settings[credentialPath])
	}
}

func TestRepository_CredentialSettings_BackfillEncryptsLegacyRowsAndIsIdempotent(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-cred-backfill")

	p := credentialPolicy(t, gwID, "cred-backfill", "placeholder")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}
	const legacySecret = "sk-legacy-backfill-target-7777"
	legacyJSON := fmt.Sprintf(`{"api_key":%q,"model":"omni-moderation-latest"}`, legacySecret)
	if _, err := conn.Pool.Exec(ctx, `UPDATE policies SET settings = $1::jsonb WHERE id = $2`, legacyJSON, p.ID); err != nil {
		t.Fatalf("force legacy plaintext row: %v", err)
	}

	n, err := r.BackfillCredentialEncryption(ctx)
	if err != nil {
		t.Fatalf("first backfill: %v", err)
	}
	if n < 1 {
		t.Fatalf("first backfill updated %d rows, want at least 1", n)
	}
	rawAfterFirst := rawSettingsField(t, conn, p.ID, credentialPath)
	if rawAfterFirst == legacySecret {
		t.Fatal("backfill did not encrypt the legacy leaf")
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after backfill: %v", err)
	}
	if got.Settings[credentialPath] != legacySecret {
		t.Fatalf("Settings[%q] = %v, want the original secret readable after backfill", credentialPath, got.Settings[credentialPath])
	}

	// Idempotency: a second pass must not touch a row it already converged,
	// and the ciphertext must not change underneath a concurrent process
	// that might be relying on it.
	n2, err := r.BackfillCredentialEncryption(ctx)
	if err != nil {
		t.Fatalf("second backfill: %v", err)
	}
	if n2 != 0 {
		t.Fatalf("second backfill updated %d rows, want 0 (already converged)", n2)
	}
	rawAfterSecond := rawSettingsField(t, conn, p.ID, credentialPath)
	if rawAfterSecond != rawAfterFirst {
		t.Fatalf("second backfill pass changed the ciphertext: %q -> %q", rawAfterFirst, rawAfterSecond)
	}

	got2, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID after second backfill: %v", err)
	}
	if got2.Settings[credentialPath] != legacySecret {
		t.Fatalf("Settings[%q] = %v, want the original secret still readable", credentialPath, got2.Settings[credentialPath])
	}
}

// The first half of RUN-1646 (response masking) must keep working end to end
// on top of leaf-level encryption: the domain still holds the real,
// decrypted value after FindByID, and secret.MaskSettings (what the HTTP
// response layer calls) still masks it for display without touching the
// stored value.
func TestRepository_CredentialSettings_MaskingStillWorksOnTopOfDecryption(t *testing.T) {
	r, gw, _ := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-cred-mask")

	const secretValue = "sk-real-secret-for-masking-4242"
	p := credentialPolicy(t, gwID, "cred-mask", secretValue)
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Settings[credentialPath] != secretValue {
		t.Fatalf("domain.Policy.Settings[%q] = %v, want the real secret held in the domain", credentialPath, got.Settings[credentialPath])
	}

	masked := secret.MaskSettings(got.Settings, []string{credentialPath})
	if masked[credentialPath] == secretValue {
		t.Fatal("MaskSettings did not mask the decrypted value")
	}
	if !secret.IsMasked(masked[credentialPath].(string)) {
		t.Fatalf("masked[%q] = %v, want a masked literal", credentialPath, masked[credentialPath])
	}
	// MaskSettings must not have mutated what plugin execution would see.
	if got.Settings[credentialPath] != secretValue {
		t.Fatalf("MaskSettings mutated the domain's own settings map: %v", got.Settings[credentialPath])
	}
}

func TestRepository_CredentialSettings_UpdateReEncryptsTheNewValue(t *testing.T) {
	r, gw, conn := setupRepo(t)
	ctx := context.Background()
	gwID := seedGateway(t, gw, "pgw-cred-update")

	p := credentialPolicy(t, gwID, "cred-update", "sk-old-secret-0001")
	if err := r.Save(ctx, p); err != nil {
		t.Fatalf("Save: %v", err)
	}

	p.Settings[credentialPath] = "sk-new-secret-0002"
	p.UpdatedAt = time.Now().UTC()
	if err := r.Update(ctx, p, true); err != nil {
		t.Fatalf("Update: %v", err)
	}

	raw := rawSettingsField(t, conn, p.ID, credentialPath)
	if raw == "sk-new-secret-0002" {
		t.Fatal("Update stored the new credential as plaintext")
	}

	got, err := r.FindByID(ctx, p.ID)
	if err != nil {
		t.Fatalf("FindByID: %v", err)
	}
	if got.Settings[credentialPath] != "sk-new-secret-0002" {
		t.Fatalf("Settings[%q] = %v, want the new secret readable after update", credentialPath, got.Settings[credentialPath])
	}
}
