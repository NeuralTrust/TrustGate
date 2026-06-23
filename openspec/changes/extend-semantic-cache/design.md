# Design: Extend the semantic_cache plugin — RUN-699

## Technical Approach

The change is **additive and in-place** on the existing `semantic_cache` plugin
(`pkg/infra/plugins/semanticcache/`) plus its store package
(`pkg/infra/cache/semantic/`). No new plugin slug, no new policy stage. The
plugin keeps its `pre_request` + `post_response` shape, its degraded
pass-through contract, and its `*adapter.Registry` / embedding-locator
dependencies. We grow four seams:

1. **Config** (`config.go`) gains the RUN-699 fields with documented precedence
   over the legacy `ttl` / nested `embedding{}` fields, and drops the hard
   `api_key` requirement.
2. **Control flow** (`plugin.go`) gains a `partitionKey` helper (replacing the
   bare `scopeID`), four request/response gates, a `mode` dispatch
   (`exact|semantic|both`), and the literal `X-Cache: HIT|MISS` header on both
   the hit and the forwarded-miss leg.
3. **Store** (`pkg/infra/cache/semantic/`) gains two exact-match methods on the
   existing `Store` interface, a `NewStore(kind, deps)` factory, and two new
   backends: `in_memory` (TTL map + cosine) and `pgvector` (pgx + a migration).
4. **DI + catalog** (`modules/plugins.go`, `catalog_metadata.go`) select the
   backend by config and expose the full schema.

All Go follows the workspace `go-comments` rule (doc comments on exported
identifiers permitted, matching the existing `semanticcache` files; **no
narrative/inline comments**), golang-pro idioms (`%w` wrapping, `context`
propagation, `-race`-clean table tests, `go vet` / `golangci-lint` clean), and
the 400-line PR budget via the five chained phases from `proposal.md`.

The exact-match path (`mode=exact|both`) is the only genuinely new storage
capability; everything else is configuration, gating, partition derivation, and
a backend factory over the already-proven `Store` contract.

## Architecture Decisions

| Decision | Choice | Rejected | Rationale |
|----------|--------|----------|-----------|
| Exact-match storage seam | Add `GetExact`/`PutExact` to the **single existing `Store` interface**; every backend implements both | Sibling `ExactStore` interface probed via `store.(ExactStore)` type assertion | One interface keeps DI/mocks singular and avoids a partial-implementation footgun and branchy assertions in the plugin; §10.1 forbids two interfaces per file, so a sibling would need its own file for no benefit. All three backends trivially support key→value+TTL. |
| Partition derivation | `partitionKey(cfg, in.Scope, req)` from config `scope` + registry id; empty consumer ⇒ pass-through | Keep `scopeID(req)` (registry/gateway only); derive from policy `RuntimeScope.Subject()` | Spec requires consumer isolation independent of policy global composition; `scope` is plugin-local. Reading ids from `in.Scope` (with registry from `req`) is the consistent source. |
| Backend selection | `NewStore(kind, deps)` factory keyed by `vector_store`; built once in DI | Per-request backend switch; reflection registry | Backend is fixed per process/config; build at wiring time; `redis` stays the default so the prior graph is unchanged. |
| `in_memory` backend | TTL map + brute-force cosine over stored vectors | LRU/size cap; sharded map | v1 simplicity; dev/test and small single-replica use; eviction is purely TTL (documented limitation). |
| `pgvector` backend | New infra store + one migration (extension + table + ivfflat index) | Reuse Redis; store vectors in a JSON column | Native `vector` type + cosine operator is the point of the backend; isolated as the heaviest final phase. |
| TTL config | `ttl_seconds` (int) wins; legacy `ttl` (duration string) alias | Replace `ttl` outright | Back-compat: existing policies keep working; precedence is explicit in `resolvedTTL()`. |
| Embedding config | Flattened `embedding_provider`/`embedding_model` win; nested `embedding{}` alias; `api_key` optional | Drop nested form | Back-compat + RUN-699 contract; missing key degrades to pass-through, never fails. |
| `X-Cache: MISS` on a miss | `pre_request` miss returns `Result{Headers:{X-Cache:[MISS]}}` **without** `StopUpstream` | Add it in `post_response`; mutate `resp.Headers` directly | Executor merges non-stop `Result.Headers` into `resp.Headers` (`executor.go:280`), forwarder snapshots them into `dto.baseHeaders` (`forwarder.go:168`) and re-applies on `finalizeBody` (`:525/545`) — so a pre_request miss header survives onto the forwarded response with no executor change. Plugins must not write `resp.Headers` directly. |
| Legacy headers | Keep `X-Cache-Status` + `X-Cache-Similarity`; add literal `X-Cache` | Replace legacy headers | Back-compat for existing dashboards. |
| Gates | `bypass_header`, `cache_only_on_status`, `skip_if_streaming`, `skip_if_tools_present` evaluated in `plugin.go` from `req.HeaderValue`, canonical decode, `resp.Streaming` | Hardcoded `Cache-Control: no-cache` only | Spec contract; `Cache-Control: no-cache` retained as an always-on bypass for back-compat. |
| Degradation | Every infra/embedding/credential error ⇒ `passThrough()` + trace `degraded` extras; request never fails | Fail closed | Preserve the current pass-through-on-error contract (Risks table). |

## Config surface — `config.go`

New struct (legacy fields retained; flattened + nested both decoded so
precedence is resolved in accessors, never by dropping a field):

```go
const (
	defaultSimilarityThreshold = 0.85
	defaultTTL                 = "24h"
	defaultTTLSeconds          = 86400
	defaultProvider            = "openai"
	defaultModel               = "text-embedding-ada-002"

	modeExact    = "exact"
	modeSemantic = "semantic"
	modeBoth     = "both"

	scopeConsumer = "consumer"
	scopeGlobal   = "global"

	storeRedis    = "redis"
	storePgvector = "pgvector"
	storeInMemory = "in_memory"

	defaultBypassHeader = "X-Cache-Bypass"
)

type embeddingConfig struct {
	Provider string `mapstructure:"provider"`
	Model    string `mapstructure:"model"`
	APIKey   string `mapstructure:"api_key"` // #nosec G101 -- config field name, not a credential
}

type config struct {
	SimilarityThreshold float64 `mapstructure:"similarity_threshold"`

	TTL        string `mapstructure:"ttl"`
	TTLSeconds int    `mapstructure:"ttl_seconds"`

	Scope       string `mapstructure:"scope"`
	Mode        string `mapstructure:"mode"`
	VectorStore string `mapstructure:"vector_store"`

	EmbeddingProvider string          `mapstructure:"embedding_provider"`
	EmbeddingModel    string          `mapstructure:"embedding_model"`
	Embedding         embeddingConfig `mapstructure:"embedding"`

	CacheOnlyOnStatus  []int  `mapstructure:"cache_only_on_status"`
	BypassHeader       string `mapstructure:"bypass_header"`
	SkipIfToolsPresent *bool  `mapstructure:"skip_if_tools_present"`
	SkipIfStreaming    bool   `mapstructure:"skip_if_streaming"`
}
```

`SkipIfToolsPresent` is `*bool` so the **default-true** semantics survive an
explicit `false` (mapstructure leaves a missing bool as `false`, which would be
indistinguishable from an intentional opt-out; the pointer disambiguates).

### Precedence resolution (accessors, not field mutation)

```go
func (c *config) resolvedTTL() time.Duration {
	if c.TTLSeconds > 0 {
		return time.Duration(c.TTLSeconds) * time.Second
	}
	if c.TTL != "" {
		if d, err := time.ParseDuration(c.TTL); err == nil && d > 0 {
			return d
		}
	}
	return defaultTTLSeconds * time.Second
}

func (c *config) provider() string {
	if c.EmbeddingProvider != "" {
		return c.EmbeddingProvider
	}
	if c.Embedding.Provider != "" {
		return c.Embedding.Provider
	}
	return defaultProvider
}

func (c *config) model() string {
	if c.EmbeddingModel != "" {
		return c.EmbeddingModel
	}
	if c.Embedding.Model != "" {
		return c.Embedding.Model
	}
	return defaultModel
}

func (c *config) mode() string {
	if c.Mode != "" {
		return c.Mode
	}
	return modeSemantic
}

func (c *config) scope() string {
	if c.Scope != "" {
		return c.Scope
	}
	return scopeConsumer
}

func (c *config) vectorStore() string {
	if c.VectorStore != "" {
		return c.VectorStore
	}
	return storeRedis
}

func (c *config) bypassHeader() string {
	if c.BypassHeader != "" {
		return c.BypassHeader
	}
	return defaultBypassHeader
}

func (c *config) skipIfTools() bool {
	if c.SkipIfToolsPresent == nil {
		return true
	}
	return *c.SkipIfToolsPresent
}

func (c *config) cacheableStatus(code int) bool {
	if len(c.CacheOnlyOnStatus) == 0 {
		return code >= 200 && code < 300
	}
	for _, s := range c.CacheOnlyOnStatus {
		if s == code {
			return true
		}
	}
	return false
}

func (c *config) embeddingDomainConfig() *embedding.Config {
	return &embedding.Config{
		Provider:    c.provider(),
		Model:       c.model(),
		Credentials: embedding.Credentials{APIKey: c.Embedding.APIKey},
	}
}
```

`embeddingDomainConfig` keeps `APIKey` only on the nested struct (no flattened
`api_key` per the proposal); it is now allowed to be empty.

### `applyDefaults` / `validate`

`applyDefaults` only seeds `SimilarityThreshold` (the rest default via the
accessors, so an empty config is valid and behaves like today). `validate`
becomes **lenient** — it rejects only malformed enums/ranges, never a missing
credential:

```go
func (c *config) validate() error {
	if c.SimilarityThreshold < 0 || c.SimilarityThreshold > 1 {
		return fmt.Errorf("semantic_cache: similarity_threshold must be in [0, 1], got %f", c.SimilarityThreshold)
	}
	if c.TTL != "" && c.TTLSeconds == 0 {
		if _, err := time.ParseDuration(c.TTL); err != nil {
			return fmt.Errorf("semantic_cache: ttl must be a valid duration: %w", err)
		}
	}
	if c.TTLSeconds < 0 {
		return fmt.Errorf("semantic_cache: ttl_seconds must be non-negative, got %d", c.TTLSeconds)
	}
	if err := validateEnum("mode", c.Mode, modeExact, modeSemantic, modeBoth); err != nil {
		return err
	}
	if err := validateEnum("scope", c.Scope, scopeConsumer, scopeGlobal); err != nil {
		return err
	}
	if err := validateEnum("vector_store", c.VectorStore, storeRedis, storePgvector, storeInMemory); err != nil {
		return err
	}
	return nil
}
```

`validateEnum` accepts `""` (defaulted later by the accessor) and otherwise
requires membership. The `api_key`-required check from the current `validate()`
is **removed** (its absence is the back-compat-breaking optional-credential
change; covered by the config test matrix). `parsedTTL()` is replaced by
`resolvedTTL()`; the old name is deleted in P1.

## Data & key formats

### Partition key — `partitionKey` (replaces `scopeID`)

```go
func partitionKey(cfg *config, scope appplugins.RuntimeScope, req *infracontext.RequestContext) (string, bool) {
	registry := registryNamespace(req)
	switch cfg.scope() {
	case scopeGlobal:
		if scope.GatewayID == "" {
			return "", false
		}
		return registry + "|g:" + scope.GatewayID, true
	default:
		if scope.ConsumerID == "" {
			return "", false
		}
		return registry + "|c:" + scope.ConsumerID, true
	}
}

func registryNamespace(req *infracontext.RequestContext) string {
	if req == nil {
		return ""
	}
	if req.RegistryID != "" {
		return req.RegistryID
	}
	return req.GatewayID
}
```

The returned `ok=false` (consumer scope, empty `ConsumerID`) is the
**pass-through** signal: the plugin no-ops the lookup and the store so a consumer
can never read another consumer's body, and an unauthenticated/consumer-less
request is never cached. The partition string is the `RuleID`/tag fed to the
store; the registry prefix preserves the "different upstreams never collide"
invariant the current `scopeID` provides. `scope.GatewayID`/`scope.ConsumerID`
come from `in.Scope` (executor-populated from the resolved consumer), not from
headers — consistent with §14.6.

### Exact key

```go
func exactKey(partition, text string) string {
	sum := sha256.Sum256([]byte(partition + "\x00" + normalize(text)))
	return hex.EncodeToString(sum[:])
}

func normalize(s string) string {
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}
```

`normalize` lower-cases and collapses runs of whitespace (the documented "last
user message only" key; history/params intentionally ignored, see proposal
non-goals). The `\x00` separator prevents partition/message boundary ambiguity.

### Redis layout implications

- **Vector entries** (semantic) are unchanged: `FT.CREATE` FLAT/COSINE index over
  `keyPrefix = "semantic_cache:"`, `rule_id` TAG = `hashID(partition)`.
- **Exact entries** live under a **separate, non-indexed** key space
  `"semantic_cache:exact:" + hashID(partition) + ":" + exactKey`, written with
  `SET ... EX <ttl>` and read with `GET`. They are not part of the RediSearch
  index (no `FT.CREATE` PREFIX overlap — the exact prefix is a strict superset of
  the vector prefix, so the index must keep its current single `PREFIX
  "semantic_cache:"` **but** the `FT.SEARCH` is already TAG-scoped by `rule_id`,
  and exact keys carry no `rule_id`/`embedding` fields, so they are invisible to
  vector search). To be safe and explicit, exact keys use the disjoint prefix
  `"semantic_cache_exact:"` so the vector index never sees them.

Final prefixes:

```
semantic_cache:<hash16>:<unixnano>      # vector HSET (existing)
semantic_cache_exact:<hashPartition>:<exactKey>   # exact SET/GET (new)
```

## Store interface evolution + factory

### `store.go` — extend the existing `Store`

```go
//go:generate mockery --name=Store --dir=. --output=./mocks --filename=store_mock.go --case=underscore --with-expecter
type Store interface {
	EnsureIndex(ctx context.Context, dimension int) error
	Lookup(ctx context.Context, ruleID string, emb *embedding.Embedding, topK int) ([]Candidate, error)
	Store(ctx context.Context, entry Entry) error

	GetExact(ctx context.Context, ruleID, key string) (string, bool, error)
	PutExact(ctx context.Context, ruleID, key, response string, ttl time.Duration) error
}
```

`ruleID` is the partition string; `key` is `exactKey(...)`. `GetExact` returns
`("", false, nil)` on a miss (not an error) so the plugin treats a miss and a
degraded backend identically (pass-through). The mock is regenerated via
`go generate`.

### `factory.go` (new) — `NewStore(kind, deps)`

```go
type Deps struct {
	Redis  *redis.Client
	Pool   *pgxpool.Pool
	Logger *slog.Logger
}

func NewStore(kind string, deps Deps) (Store, error) {
	switch kind {
	case "", "redis":
		if deps.Redis == nil {
			return nil, fmt.Errorf("semantic: redis store requires a redis client")
		}
		return NewRedisStore(deps.Redis, deps.Logger), nil
	case "in_memory":
		return NewMemoryStore(deps.Logger), nil
	case "pgvector":
		if deps.Pool == nil {
			return nil, fmt.Errorf("semantic: pgvector store requires a database pool")
		}
		return NewPgvectorStore(deps.Pool, deps.Logger), nil
	default:
		return nil, fmt.Errorf("semantic: unknown vector_store %q", kind)
	}
}
```

The factory is keyed by the **config** `vector_store`. Because a policy's
`vector_store` is per-policy config but the store is a process-level dependency,
the DI graph builds the store from a single env-backed default (see DI section);
the plugin trusts the injected store and records the configured backend in trace
extras. (A genuinely multi-backend-per-policy registry is an open question, see
below — for v1 the configured `vector_store` selects the process store and a
mismatch is a documented operator constraint.)

### `RedisStore` exact methods (`store.go`)

```go
const exactKeyPrefix = "semantic_cache_exact:"

func (s *RedisStore) GetExact(ctx context.Context, ruleID, key string) (string, bool, error) {
	full := exactKeyPrefix + hashID(ruleID) + ":" + key
	val, err := s.client.Get(ctx, full).Result()
	if errors.Is(err, redis.Nil) {
		return "", false, nil
	}
	if err != nil {
		return "", false, nil
	}
	return val, true, nil
}

func (s *RedisStore) PutExact(ctx context.Context, ruleID, key, response string, ttl time.Duration) error {
	full := exactKeyPrefix + hashID(ruleID) + ":" + key
	if err := s.client.Set(ctx, full, response, ttl).Err(); err != nil {
		return fmt.Errorf("semantic: put exact entry: %w", err)
	}
	return nil
}
```

### `memory_store.go` (new) — `in_memory`

A mutex-guarded TTL map for exact entries plus a per-rule slice of
`{vector []float32, response string, expiry time.Time}` for semantic lookups.
`Lookup` brute-forces cosine over the rule's live (unexpired) entries and returns
the top-K. `EnsureIndex` is a no-op. Eviction is lazy on read + an opportunistic
sweep; vector dimension is taken from the first stored vector.

```go
type MemoryStore struct {
	mu     sync.Mutex
	exact  map[string]memEntry           // exactKeyPrefix composite -> value+expiry
	vec    map[string][]memVector        // ruleID -> vectors
	logger *slog.Logger
}

func NewMemoryStore(logger *slog.Logger) *MemoryStore { ... }
```

Cosine similarity is computed as `dot(a,b) / (‖a‖·‖b‖)` to match the Redis
`1 - cosine_distance` semantics the plugin already compares against
`SimilarityThreshold`.

### `pgvector_store.go` (new) — `pgvector`

```go
type PgvectorStore struct {
	pool    *pgxpool.Pool
	logger  *slog.Logger
	ensured atomic.Bool
	mu      sync.Mutex
}

func NewPgvectorStore(pool *pgxpool.Pool, logger *slog.Logger) *PgvectorStore { ... }
```

- `EnsureIndex(ctx, dim)` is a no-op for schema (the migration owns DDL); it may
  validate the column dimension once and set `ensured`.
- `Lookup` runs `SELECT response, 1 - (embedding <=> $1) AS similarity FROM
  semantic_cache_entries WHERE rule_id = $2 ORDER BY embedding <=> $1 LIMIT $3`
  (`<=>` = cosine distance), mapping rows to `Candidate`. The embedding is sent
  as a `pgvector` literal built from `entry.Embedding.Value`.
- `Store` inserts `(rule_id, embedding, response, expires_at)`.
- `GetExact`/`PutExact` use a second table `semantic_cache_exact` keyed
  `(rule_id, key)` with `expires_at`; `GetExact` filters `expires_at > now()`.
- TTL: store `expires_at = now() + ttl`; a partial index / a periodic
  `DELETE WHERE expires_at < now()` sweep handles eviction (documented; a
  pg_cron/job is out of scope — reads filter on `expires_at`).

All query errors and a missing extension degrade to `nil`/`("",false,nil)` so the
plugin passes through (never fails traffic).

## pgvector migration — `pkg/infra/database/migrations/<ts>_add_semantic_cache_pgvector.go`

In-code migration registered via `init()`, idempotent up + down in one tx,
mirroring the existing migration shape:

```sql
-- Up
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS semantic_cache_entries (
    id          BIGSERIAL PRIMARY KEY,
    rule_id     TEXT        NOT NULL,
    embedding   vector(1536) NOT NULL,
    response    TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS semantic_cache_entries_rule_idx
    ON semantic_cache_entries (rule_id);
CREATE INDEX IF NOT EXISTS semantic_cache_entries_vec_idx
    ON semantic_cache_entries USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
CREATE INDEX IF NOT EXISTS semantic_cache_entries_exp_idx
    ON semantic_cache_entries (expires_at);

CREATE TABLE IF NOT EXISTS semantic_cache_exact (
    rule_id     TEXT        NOT NULL,
    key         TEXT        NOT NULL,
    response    TEXT        NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (rule_id, key)
);
CREATE INDEX IF NOT EXISTS semantic_cache_exact_exp_idx
    ON semantic_cache_exact (expires_at);

-- Down
DROP TABLE IF EXISTS semantic_cache_exact;
DROP TABLE IF EXISTS semantic_cache_entries;
-- extension left in place (other features may use it); documented in the migration Name.
```

`vector(1536)` matches `defaultVectorDimension`. **Open risk:** a non-1536
embedding model breaks the fixed column dim (see open questions). The migration
file carries a `..._test.go` sibling asserting up/down register and apply
cleanly against a `PG_TEST_URL` (deferred per AGENT.md §9, gated on the env var).
This is the only stateful change and ships as the isolated final phase (P5); it
is inert unless `vector_store: pgvector` is configured.

## Plugin control flow — `plugin.go`

`Plugin` gains no new struct fields except the injected `store` already present.
`Execute` keeps the degraded-pass-through preamble and adds the bypass gate up
front; stage handlers consume the resolved config.

```go
func (p *Plugin) Execute(ctx context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	cfg, err := parseConfig(in.Config.Settings)
	if err != nil {
		return nil, fmt.Errorf("semantic_cache: %w", err)
	}

	if p.bypassed(in.Request, cfg) {
		setCacheExtras(in.Event, SemanticCacheData{Bypassed: true, Mode: cfg.mode(), Scope: cfg.scope()})
		if in.Stage == policy.StagePreRequest {
			markStatus(in.Response, cacheStatusMiss)
			return missResult(), nil
		}
		return passThrough(), nil
	}

	partition, ok := partitionKey(cfg, in.Scope, in.Request)
	if !ok {
		setCacheExtras(in.Event, SemanticCacheData{Degraded: true, DegradedReason: "no_partition", Scope: cfg.scope()})
		if in.Stage == policy.StagePreRequest {
			markStatus(in.Response, cacheStatusMiss)
			return missResult(), nil
		}
		return passThrough(), nil
	}

	switch in.Stage {
	case policy.StagePreRequest:
		return p.preRequest(ctx, in, cfg, partition)
	case policy.StagePostResponse:
		return p.postResponse(ctx, in, cfg, partition)
	default:
		return passThrough(), nil
	}
}
```

`bypassed` folds the legacy `Cache-Control: no-cache`, the configured
`bypass_header`, and `skip_if_streaming` (request side) into one predicate:

```go
func (p *Plugin) bypassed(req *infracontext.RequestContext, cfg *config) bool {
	if noCache(req) {
		return true
	}
	if req.HeaderValue(cfg.bypassHeader()) != "" {
		return true
	}
	if cfg.SkipIfStreaming && p.requestWantsStream(req) {
		return true
	}
	return false
}
```

`requestWantsStream` decodes the canonical request and reads `Stream`
(falls back to a generic `"stream":true` check), mirroring `DetectStream` in the
forwarder. `index` / embedding-service acquisition stays inside the
semantic-only paths (exact mode needs neither), so an `index_unavailable` or
`embedding_service_unavailable` failure only degrades semantic lookups.

`missResult()` returns the literal MISS header without stopping upstream:

```go
func missResult() *appplugins.Result {
	return &appplugins.Result{
		StatusCode: http.StatusOK,
		Headers: map[string][]string{
			"X-Cache":        {cacheStatusMiss},
			"X-Cache-Status": {cacheStatusMiss},
		},
	}
}
```

### `preRequest` per mode + gates

```go
func (p *Plugin) preRequest(ctx, in, cfg, partition) (*appplugins.Result, error)
```

Flow:

1. **tools gate (serve side):** if `cfg.skipIfTools()` and the request declares
   tools (`canonical.Tools` non-empty), record `skip_reason=tools_present`,
   `markStatus(MISS)`, return `missResult()`. (Storing-side tools gate is in
   `postResponse`.)
2. `text := extractUserInput(req)`; empty ⇒ `markStatus(MISS)`, `missResult()`.
3. **exact lookup** (mode `exact` or `both`): `resp, hit, _ := store.GetExact(ctx,
   partition, exactKey(partition, text))`. On `hit` in `enforce` mode ⇒ serve
   (HIT). In `observe` ⇒ `markStatus(MISS)`, record hit-without-serve. If
   `mode == exact` and no hit ⇒ `missResult()`.
4. **semantic lookup** (mode `semantic` or `both` fallthrough): ensure index +
   embedding service (degrade to pass-through on failure), generate embedding,
   `store.Lookup(ctx, partition, emb, 1)`; compare `Similarity` ≥
   `SimilarityThreshold`. `observe` never serves. On a serve, build the HIT
   result.
5. miss ⇒ `markStatus(MISS)`, `missResult()`.

The HIT result keeps `StopUpstream: true` and adds the literal header alongside
the legacy ones:

```go
func hitResult(body []byte, similarity float64, exact bool) *appplugins.Result {
	headers := map[string][]string{
		"X-Cache":        {cacheStatusHit},
		"X-Cache-Status": {cacheStatusHit},
	}
	if !exact {
		headers["X-Cache-Similarity"] = []string{fmt.Sprintf("%.4f", similarity)}
	}
	return &appplugins.Result{
		StatusCode:   http.StatusOK,
		Body:         body,
		StopUpstream: true,
		Headers:      headers,
	}
}
```

### `postResponse` per mode + gates

```go
func (p *Plugin) postResponse(ctx, in, cfg, partition) (*appplugins.Result, error)
```

1. `resp == nil || len(resp.Body) == 0` ⇒ pass-through.
2. **status gate:** `!cfg.cacheableStatus(resp.StatusCode)` ⇒ pass-through
   (`skip_reason=status`).
3. `in.Mode == observe` ⇒ pass-through (no store), record `stored=false`.
4. `statusOf(resp) == HIT` ⇒ pass-through (already served).
5. **streaming gate:** `cfg.SkipIfStreaming && resp.Streaming` ⇒ pass-through
   (`skip_reason=streaming`).
6. **tools gate (store side):** `cfg.skipIfTools()` and (`canonical.Tools`
   non-empty OR response `ToolCalls` non-empty OR `FinishReason == "tool_calls"`)
   ⇒ pass-through (`skip_reason=tools_present`).
7. `text := extractUserInput(req)`; empty ⇒ pass-through.
8. **store per mode:**
   - `exact` or `both`: `store.PutExact(ctx, partition, exactKey(partition,
     text), string(resp.Body), cfg.resolvedTTL())`.
   - `semantic` or `both`: generate embedding (degrade on failure), `store.Store(
     ctx, Entry{RuleID: partition, Embedding: emb, Response: string(resp.Body),
     TTL: cfg.resolvedTTL()})`.
   - `both` stores under **both** (a `PutExact` failure does not block the
     semantic store and vice-versa; either failure is a degraded trace, not a
     request failure).
9. record `stored=true` extras.

Tool detection reuses `p.registry.DecodeRequestFor(req.Body, format)` /
`DecodeResponseFor` (already a dependency); decode failure is treated as "no
tools" (fail-open for the gate) and recorded.

### X-Cache MISS mechanism (no executor change)

On a miss, `preRequest` returns `missResult()` with `StopUpstream=false`.
`executor.applyResults` merges those headers into `resp.Headers`
(`executor.go:280-282`) even though the result does not stop upstream. The
forwarder snapshots `resp.Headers` into `dto.baseHeaders` immediately after
`runPreRequest` (`forwarder.go:168`) and re-seeds `pluginResp.Headers =
cloneHeaders(dto.baseHeaders)` in both `finalizeBody` and `finalizeBodyGated`
(`:525`, `:545`) before merging provider headers. Net: `X-Cache: MISS` rides
through to the forwarded response with **zero** changes to the executor or
forwarder. This is asserted by a functional test (open question: confirm
`mergeProviderResponse` does not strip a pre-seeded `X-Cache`).

## Observability — `data.go`

`SemanticCacheData` grows additive, `omitempty` fields (no breaking change to
existing trace consumers):

```go
type SemanticCacheData struct {
	CacheHit       bool    `json:"cache_hit"`
	Similarity     float64 `json:"similarity,omitempty"`
	Threshold      float64 `json:"threshold"`
	EmbeddingSize  int     `json:"embedding_size,omitempty"`
	VectorDim      int     `json:"vector_dimension,omitempty"`
	Stored         bool    `json:"stored"`
	Degraded       bool    `json:"degraded,omitempty"`
	DegradedReason string  `json:"degraded_reason,omitempty"`

	Mode       string `json:"mode,omitempty"`
	Scope      string `json:"scope,omitempty"`
	VectorStore string `json:"vector_store,omitempty"`
	MatchType  string `json:"match_type,omitempty"`  // "exact" | "semantic"
	Bypassed   bool   `json:"bypassed,omitempty"`
	SkipReason string `json:"skip_reason,omitempty"` // "tools_present" | "streaming" | "status"
}
```

## DI wiring — `pkg/container/modules/plugins.go`

`pluginParams` gains the DB pool so the factory can build `pgvector`:

```go
type pluginParams struct {
	dig.In
	Cache    cache.Client
	Adapters *adapter.Registry
	Locator  embeddingfactory.EmbeddingServiceLocator
	Logger   *slog.Logger
	Pricing  appcatalog.PricingResolver
	DB       *database.Connection
}
```

`newPluginRegistry` selects the backend from an env-backed default
(`SEMANTIC_CACHE_VECTOR_STORE`, default `redis`) so the process store matches the
configured backend without a per-policy switch:

```go
store, err := semantic.NewStore(p.vectorStoreKind(), semantic.Deps{
	Redis:  redisClient,
	Pool:   poolOrNil(p.DB),
	Logger: p.Logger,
})
if err != nil {
	return nil, err
}
...
semanticcache.New(store, p.Locator, p.Adapters),
```

`redis` stays the default, so the existing graph is byte-for-byte unchanged when
the env var is unset. `poolOrNil` guards a nil `*database.Connection` (admin/test
graphs that omit it). The exact env-var name/source is an open question (could be
a `*config.Config` field per AGENT.md §6 instead of an ad-hoc env read); P3
resolves it. **Phase note:** P3 introduces `NewStore` + `in_memory` + the
`pluginParams.DB`/env plumbing; `pgvector` wiring lands with P5.

## Catalog metadata — `catalog_metadata.go`

Extend the existing `"semantic_cache"` `SettingsSchema.Fields` (keep
`similarity_threshold`, `ttl`, `embedding{}`; **drop `embedding.Required` and
`api_key.Required`**). Add:

- `mode` — `FieldTypeEnum`, `["exact","semantic","both"]`, default `"semantic"`.
- `scope` — `FieldTypeEnum`, `["consumer","global"]`, default `"consumer"`,
  description "Cache partition; consumer isolates per consumer, global per
  gateway" (mirrors the `per_tool_rate_limiter` `scope` enum precedent at
  `catalog_metadata.go:500`).
- `vector_store` — `FieldTypeEnum`, `["redis","pgvector","in_memory"]`, default
  `"redis"`.
- `ttl_seconds` — `FieldTypeInteger`, description "TTL in seconds; overrides
  ttl when set".
- `embedding_provider` / `embedding_model` — `FieldTypeString` (flattened
  aliases).
- `cache_only_on_status` — `FieldTypeArray`, `Item` `FieldTypeInteger`, default
  `[200]`.
- `bypass_header` — `FieldTypeString`, default `"X-Cache-Bypass"`.
- `skip_if_tools_present` — `FieldTypeBoolean`, default `true`.
- `skip_if_streaming` — `FieldTypeBoolean`, default `false`.

`catalog_test.go` is extended to assert the new field keys/types/enums/defaults
and that `embedding` is no longer `Required`. Updated **per phase** to avoid
schema/plugin drift (Risks table).

## Back-compat strategy

| Legacy input | New behaviour |
|---|---|
| `ttl: "24h"`, no `ttl_seconds` | `resolvedTTL()` parses the duration string. |
| `ttl_seconds: 3600` + `ttl: "24h"` | `ttl_seconds` wins (3600s). |
| nested `embedding{provider,model,api_key}` only | `provider()/model()` read the nested struct; `api_key` used if present. |
| flattened `embedding_provider`/`_model` + nested | flattened win for provider/model; `api_key` still from nested. |
| no `embedding.api_key` | accepted; semantic paths degrade to pass-through on credential/embedding error. |
| no `scope` | defaults `consumer` (the only behavioural default change; guarded by empty-consumer pass-through so it cannot leak or hard-fail). |
| no `mode`/`vector_store` | default `semantic`/`redis` ⇒ today's behaviour. |
| `Cache-Control: no-cache` | still bypasses (folded into `bypassed`). |
| existing `X-Cache-Status`/`X-Cache-Similarity` consumers | preserved verbatim; `X-Cache` added alongside. |

## Error & degradation handling

- Config parse error ⇒ `Execute` returns `fmt.Errorf("semantic_cache: %w", err)`
  (the only hard error; a malformed policy should surface, as today).
- `partitionKey` `ok=false`, index unavailable, embedding service/credential
  failure, store `Lookup`/`Store`/`GetExact`/`PutExact` errors ⇒ **pass-through**
  with a `degraded`/`skip_reason` trace; the request never fails.
- `GetExact` returns `("",false,nil)` on a miss so miss and degraded backend are
  indistinguishable to the plugin (both pass through).
- `both` mode: exact and semantic store failures are independent; one failing
  does not block the other and neither fails the request.
- `context` is propagated to every store/embedding call for cancellation; no
  goroutines are spawned by the plugin (the executor owns concurrency).

## Phase mapping (chained PRs, ≤400 lines each)

| Phase | Files | Deliverable |
|---|---|---|
| **P1** | `config.go`, `plugin.go` (header + status gate + bypass + optional key), `data.go`, `catalog_metadata.go`(+test), `plugin_test.go` | Config surface + back-compat precedence, optional `api_key`, `cache_only_on_status`, `bypass_header`, literal `X-Cache: HIT\|MISS`. No partition/store/mode change. |
| **P2** | `plugin.go` (`partitionKey`, streaming + tools gates), `data.go`, `plugin_test.go` | Consumer/global partition via `in.Scope` (registry-namespaced, empty-consumer pass-through) + `skip_if_streaming` + `skip_if_tools_present`. |
| **P3** | `store.go` (interface + Redis exact methods), `factory.go`, `memory_store.go`, `modules/plugins.go` (factory + `pluginParams.DB`/env), mocks | `Store` factory keyed by `vector_store` + `in_memory` backend + DI. `redis` default unchanged. |
| **P4** | `config.go`(mode accessor already in P1), `plugin.go` (exact dispatch in pre/post), `plugin_test.go` | `mode` `exact`/`both` (deterministic hashed match + semantic fallback + dual store). Split `exact` vs `both` if over budget. |
| **P5** | `pgvector_store.go`, `migrations/<ts>_add_semantic_cache_pgvector.go`(+test), `modules/plugins.go` (pgvector branch), `factory.go` | `pgvector` backend + migration (extension + tables + indexes). Inert unless configured. |

If P1 approaches budget, split config-vs-catalog. P4 splits `exact`-then-`both`.

## Test plan (table-driven, `go test -race ./...`)

- **Config (`config_test.go` / `plugin_test.go`)** — matrix over: legacy `ttl`
  only; `ttl_seconds` only; both (seconds win); nested embedding only; flattened
  only; both (flattened win); missing `api_key` (valid now); `similarity_threshold`
  out of range (error); bad `mode`/`scope`/`vector_store` enum (error); empty
  config (defaults). Assert `resolvedTTL`, `provider`, `model`, `mode`, `scope`,
  `vectorStore`, `skipIfTools`, `cacheableStatus`.
- **Partition** — consumer scope keys on `ConsumerID`; global on `GatewayID`;
  empty `ConsumerID` ⇒ `ok=false` ⇒ pass-through + MISS; two registries ⇒
  distinct partitions (no collision); registry-empty falls back to gateway.
- **Gates** — `bypass_header` present (skip + MISS) / absent; `Cache-Control:
  no-cache` still bypasses; `cache_only_on_status` allows `[200]` blocks `201`
  when configured `[200]`, allows custom list; `skip_if_streaming` true blocks
  store on `resp.Streaming` and blocks lookup on request stream; `skip_if_tools_
  present` true skips serve on request `Tools`, skips store on request `Tools` /
  response `ToolCalls` / `FinishReason=="tool_calls"`; default-true survives
  explicit `false` (pointer).
- **Headers** — HIT path returns `X-Cache: HIT` (+ legacy); miss path returns
  `X-Cache: MISS` via `missResult`; observe never serves; functional test asserts
  MISS survives onto the forwarded response.
- **Store factory** — `NewStore` selects redis/in_memory/pgvector; unknown kind
  errors; nil deps error for redis/pgvector. `MemoryStore` TTL eviction (entry
  expires after `ttl`); cosine ordering top-K; exact get/put round-trip.
- **Mode** — `exact` hit/miss on normalized message (case + whitespace
  insensitive); `semantic` threshold boundary (≥ serves, < misses); `both`
  exact-first then semantic fallback; `both` stores under both backends; one
  store failure does not fail the request.
- **Degradation** — index error, embedding error, locator error, store error,
  `GetExact`/`PutExact` error ⇒ pass-through, no error returned, `degraded` trace.
- **Catalog** — `catalog_test.go` asserts new fields/types/enums/defaults and
  `embedding` no longer required.
- **Functional (`tests/functional/`)** — end-to-end HIT/MISS, bypass header,
  consumer isolation (consumer B never sees consumer A's body), streaming-skip,
  tools-skip; pgvector against `PG_TEST_URL` (P5, env-gated per AGENT.md §9).

Tests use the existing `fakeStore`/`fakeCreator` doubles (extended with
`GetExact`/`PutExact`) and the real `adapter.NewRegistry()` for canonical
decode, matching the current `plugin_test.go`.

## New open questions (the 10 decisions in the prompt are settled)

1. **Per-policy `vector_store` vs process store.** The factory is process-level
   (DI), but `vector_store` is per-policy config. v1 selects the process backend
   from an env/`config` default and treats a per-policy mismatch as an operator
   constraint (trace records the configured value). If true per-policy backends
   are required, a `map[kind]Store` registry injected into the plugin is the
   follow-up. Resolve in P3.
2. **DB pool availability in every graph.** `pluginParams.DB` must be optional
   (`poolOrNil`) because admin/test graphs may omit `*database.Connection`;
   confirm the proxy graph always provides it and that adding the field to
   `pluginParams` does not break a minimal test container (`container.New` +
   selective modules, AGENT.md §9). Resolve in P3.
3. **pgvector column dimension vs embedding model.** The migration hardcodes
   `vector(1536)` (= `defaultVectorDimension`). A non-1536 embedding model breaks
   inserts. Options: make the dim configurable (migration can't easily be
   parametric), validate dim at store init and degrade, or document 1536-only for
   the pgvector backend. Resolve in P5.
4. **`mergeProviderResponse` and the seeded `X-Cache: MISS`.** Confirm
   `mergeProviderResponse(pluginResp, providerResp, false)` appends/merges rather
   than replacing `pluginResp.Headers`, so the pre-seeded `X-Cache: MISS` is not
   clobbered by upstream headers. Add a functional assertion. Resolve in P1.
5. **RediSearch prefix disjointness.** The exact key prefix
   `semantic_cache_exact:` is a *prefix-string* superset of the index prefix
   `semantic_cache:` (former starts with the latter). Confirm the FT index's
   `PREFIX "semantic_cache:"` does **not** index exact keys (it would, since
   `semantic_cache_exact:` begins with `semantic_cache:`). **Mitigation:** change
   the exact prefix to a fully disjoint namespace (e.g. `sc_exact:`) so the index
   never matches it; the design above already isolates exact entries logically,
   but the literal prefix must not start with `semantic_cache:`. Resolve in P4
   (decide the final exact prefix string before writing the Redis exact methods).
6. **`skip_if_streaming:false` replay fidelity.** Caching a buffered SSE stream
   and replaying it verbatim on a hit is the documented limitation (proposal
   non-goals); confirm `post_response` sees the fully buffered body for streamed
   responses (`wrapStreamWithPostResponse`) before relying on it. Out of scope to
   fix; flag if the buffer is unavailable. Resolve in P2/P4.
