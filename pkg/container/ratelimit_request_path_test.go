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

package container_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	mcphttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/mcp"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	ratelimitapp "github.com/NeuralTrust/TrustGate/pkg/app/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/container"
	"github.com/NeuralTrust/TrustGate/pkg/container/modules"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/database"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

// redisCalls counts every command that reaches the wire, including those inside
// a pipeline, except the server introspection (CONFIG, INFO) that the MCP vault
// runs once at boot to warn about a Redis that can evict credentials. That probe
// is asynchronous and unrelated to a request, so counting it would make the test
// depend on how fast the process booted.
type redisCalls struct {
	n     atomic.Int64
	names sync.Map
}

func (c *redisCalls) DialHook(next redis.DialHook) redis.DialHook { return next }
func (c *redisCalls) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if name := cmd.Name(); name != "config" && name != "info" {
			c.n.Add(1)
			c.names.Store(cmd.String(), true)
		}
		return next(ctx, cmd)
	}
}
func (c *redisCalls) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		c.n.Add(int64(len(cmds)))
		return next(ctx, cmds)
	}
}

// plansSnapshot loads a snapshot with one stamped gateway of a tenant whose row
// caps it at burst requests a minute.
func plansSnapshot(t *testing.T, store configsync.ConfigStore[*readmodel.Snapshot], burst int) ids.GatewayID {
	t.Helper()
	gw := ids.New[ids.GatewayKind]()
	b, q, m := 1_000_000, 1_000_000, 5
	g := gatewaydomain.Gateway{
		ID:           gw,
		Slug:         "acme",
		Metadata:     map[string]string{gatewaydomain.MetadataTenantIDKey: "acme"},
		Entitlements: gatewaydomain.Entitlements{Tier: "free", BurstPerMin: &b, QuotaPerMonth: &q, MaxInstances: &m},
	}
	store.Swap(&configsync.Versioned[*readmodel.Snapshot]{Version: "v1", Snapshot: readmodel.Build(readmodel.Data{
		Gateways:   []gatewaydomain.Gateway{g},
		TenantCaps: []ratelimitdomain.TenantCaps{{TenantID: "acme", Tier: "free", BurstPerMin: burst, QuotaPerMonth: 100_000, MaxInstances: 5}},
	})})
	return gw
}

func routable(gw ids.GatewayID) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Name: "c", Slug: "cons1234",
	}}
}

type requestPathDeps struct {
	shared *redisCalls
	sync   *redisCalls
	meter  *ratelimitapp.Meter
	store  configsync.ConfigStore[*readmodel.Snapshot]
}

// hook installs a call counter on the process-wide Redis client and on the
// rate limiter's own sync client of a freshly built plane.
func hook(t *testing.T, c *container.Container) requestPathDeps {
	t.Helper()
	d := requestPathDeps{shared: &redisCalls{}, sync: &redisCalls{}}
	if err := c.Invoke(func(
		cl cache.Client,
		sc *cache.SyncClient,
		meter *ratelimitapp.Meter,
		store configsync.ConfigStore[*readmodel.Snapshot],
	) {
		cl.RedisClient().AddHook(d.shared)
		sc.AddHook(d.sync)
		d.meter, d.store = meter, store
		t.Cleanup(func() { _ = sc.Close() })
	}); err != nil {
		t.Fatalf("resolve the rate limiter: %v", err)
	}
	if d.meter == nil {
		t.Fatal("the meter is nil with the limiter on")
	}
	return d
}

// The headline property: a proxied request never makes a Redis call. Both
// clients are hooked, 30 requests are charged (5 admitted, 25 refused with a
// 429 from memory), and neither has seen a command. Redis is reached only when
// the sync runs, through the sync client, once per round.
func TestRateLimit_ProxyForwardPathMakesZeroRedisCalls(t *testing.T) {
	setDBLessSmokeEnv(t)
	c, err := container.New(modules.All("proxy", true)...)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	d := hook(t, c)
	gw := plansSnapshot(t, d.store, 5)

	var tooMany, forwarded int
	if err := c.Invoke(func(fwd appproxy.Forwarder) {
		for i := 0; i < 30; i++ {
			res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gw, Consumer: routable(gw), Request: &infracontext.RequestContext{},
			})
			if err == nil && res != nil && res.StatusCode == http.StatusTooManyRequests {
				tooMany++
			} else {
				forwarded++
			}
		}
	}); err != nil {
		t.Fatalf("resolve the forwarder: %v", err)
	}
	if forwarded != 5 || tooMany != 25 {
		t.Fatalf("admitted %d and refused %d, want 5 and 25: the tenant row (5/min) must be the cap", forwarded, tooMany)
	}
	if got := d.shared.n.Load(); got != 0 {
		t.Fatalf("the shared Redis client received %d commands on the forward path, want 0", got)
	}
	if got := d.sync.n.Load(); got != 0 {
		t.Fatalf("the sync client received %d commands on the forward path, want 0", got)
	}

	if err := d.meter.SyncNow(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if got := d.sync.n.Load(); got == 0 {
		t.Fatal("the sync did not reach Redis through the sync client: usage would never be shared between pods")
	}
	if got := d.shared.n.Load(); got != 0 {
		t.Fatalf("the sync must not use the shared client either, got %d commands", got)
	}
}

// The MCP data plane charges tools/call the same way: in memory, no Redis call.
func TestRateLimit_MCPToolsCallPathMakesZeroRedisCalls(t *testing.T) {
	setDBLessSmokeEnv(t)
	c, err := container.New(modules.All("mcp", true)...)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	d := hook(t, c)
	gw := plansSnapshot(t, d.store, 5)

	params, _ := json.Marshal(map[string]any{"name": "no_such_tool"})
	var limited, other int
	if err := c.Invoke(func(g *mcphttp.RPCGateway) {
		for i := 0; i < 30; i++ {
			_, err := g.Dispatch(context.Background(), routable(gw), "tools/call", params)
			var rpc interface{ ResolvedHTTPStatus() int }
			if errors.As(err, &rpc) && rpc.ResolvedHTTPStatus() == http.StatusTooManyRequests {
				limited++
			} else {
				other++
			}
		}
	}); err != nil {
		t.Fatalf("resolve the MCP gateway: %v", err)
	}
	if other != 5 || limited != 25 {
		t.Fatalf("admitted %d and refused %d, want 5 and 25", other, limited)
	}
	if got := d.shared.n.Load(); got != 0 {
		var seen []string
		d.shared.names.Range(func(k, _ any) bool { seen = append(seen, k.(string)); return true })
		t.Fatalf("the shared Redis client received %d commands on the tools/call path (%v), want 0", got, seen)
	}
	if got := d.sync.n.Load(); got != 0 {
		t.Fatalf("the sync client received %d commands on the tools/call path, want 0", got)
	}
	if err := d.meter.SyncNow(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if d.sync.n.Load() == 0 || d.shared.n.Load() != 0 {
		t.Fatalf("only the sync client may reach Redis: sync=%d shared=%d", d.sync.n.Load(), d.shared.n.Load())
	}
}

// A DB-less plane still wires the limiter.
func TestRateLimit_SnapshotPlaneMeters(t *testing.T) {
	setDBLessSmokeEnv(t)
	c, err := container.New(modules.All("proxy", true)...)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	if err := c.Invoke(func(meter *ratelimitapp.Meter, sc *cache.SyncClient) {
		defer func() { _ = sc.Close() }()
		if meter == nil {
			t.Fatal("the meter is not wired")
		}
	}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
}

// With the limiter off nothing meters and nothing syncs: no meter to start, and
// the request path gets the no-op checker.
func TestRateLimit_DisabledWiresNoMeter(t *testing.T) {
	setDBLessSmokeEnv(t)
	t.Setenv("RATE_LIMIT_ENABLED", "false")
	c, err := container.New(modules.All("proxy", true)...)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	if err := c.Invoke(func(meter *ratelimitapp.Meter, checker ratelimitapp.Checker, sc *cache.SyncClient) {
		if sc != nil {
			_ = sc.Close()
			t.Fatal("a disabled limiter must not build a sync client (nor its credentials provider)")
		}
		if meter != nil {
			t.Fatal("a disabled limiter must not build a meter")
		}
		if checker.Check(context.Background(), ids.New[ids.GatewayKind]()) != nil {
			t.Fatal("the no-op checker never refuses")
		}
	}); err != nil {
		t.Fatalf("resolve: %v", err)
	}
}

// fakeGateways answers the one lookup the limiter makes on a Postgres plane
// (the finder's FindByID, behind an in-memory TTL cache). Everything else on the
// embedded nil interface would panic, which is the point: the request path must
// not need it.
type fakeGateways struct {
	gatewaydomain.Repository
	gw *gatewaydomain.Gateway
}

func (f fakeGateways) FindByID(_ context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error) {
	if id != f.gw.ID {
		return nil, gatewaydomain.ErrNotFound
	}
	return f.gw, nil
}

// fakeTenantCaps stands in for the tenant_entitlements table: the only query the
// caps cache runs.
type fakeTenantCaps struct {
	ratelimitdomain.TenantCapsRepository
	caps []ratelimitdomain.TenantCaps
}

func (f fakeTenantCaps) ListTenantCaps(context.Context) ([]ratelimitdomain.TenantCaps, error) {
	return f.caps, nil
}

// setPostgresPlaneEnv is the environment of a plane that is NOT DB-less, minus
// Postgres itself: the gateway repository and the tenant_entitlements lister
// are replaced by fakes below, so no connection is ever opened.
func setPostgresPlaneEnv(t *testing.T) {
	t.Helper()
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis: %v", err)
	}
	t.Cleanup(mr.Close)
	t.Setenv("REDIS_HOST", mr.Host())
	t.Setenv("REDIS_PORT", mr.Port())
	t.Setenv("GATEWAY_BASE_DOMAIN", "example.com")
	t.Setenv("SERVER_SECRET_KEY", smokeSecretKey())
}

// postgresPlane builds the full (non DB-less) module graph for plane, swaps the
// gateway repository and the tenant caps lister for in-memory fakes, loads the
// caps copy once, and returns the hooked clients plus the gateway to charge.
func postgresPlane(t *testing.T, plane string, burst int) (requestPathDeps, *container.Container, ids.GatewayID) {
	t.Helper()
	setPostgresPlaneEnv(t)
	c, err := container.New(modules.All(plane, false)...)
	if err != nil {
		t.Fatalf("container: %v", err)
	}
	gwID := ids.New[ids.GatewayKind]()
	gw := &gatewaydomain.Gateway{
		ID: gwID, Slug: "acme",
		Metadata: map[string]string{gatewaydomain.MetadataTenantIDKey: "acme"},
	}
	// The graph builds a *database.Connection for the gateway repository; the
	// fakes replace both consumers of it, and nothing else on these paths reads it.
	if err := c.Decorate(func() *database.Connection { return &database.Connection{} }); err != nil {
		t.Fatalf("decorate connection: %v", err)
	}
	if err := c.Decorate(func() gatewaydomain.Repository { return fakeGateways{gw: gw} }); err != nil {
		t.Fatalf("decorate gateways: %v", err)
	}
	if err := c.Decorate(func() ratelimitdomain.TenantCapsRepository {
		return fakeTenantCaps{caps: []ratelimitdomain.TenantCaps{
			{TenantID: "acme", Tier: "free", BurstPerMin: burst, QuotaPerMonth: 100_000, MaxInstances: 5},
		}}
	}); err != nil {
		t.Fatalf("decorate tenant caps: %v", err)
	}

	d := requestPathDeps{shared: &redisCalls{}, sync: &redisCalls{}}
	if err := c.Invoke(func(
		cl cache.Client,
		sc *cache.SyncClient,
		meter *ratelimitapp.Meter,
		caps *ratelimitapp.TenantCapsCache,
	) {
		cl.RedisClient().AddHook(d.shared)
		sc.AddHook(d.sync)
		d.meter = meter
		t.Cleanup(func() { _ = sc.Close() })
		if caps == nil {
			t.Fatal("a Postgres plane must hold the tenant caps copy")
		}
		if err := caps.Load(context.Background()); err != nil {
			t.Fatalf("load the caps copy: %v", err)
		}
	}); err != nil {
		t.Fatalf("resolve the rate limiter: %v", err)
	}
	if d.meter == nil {
		t.Fatal("the meter is nil with the limiter on")
	}
	return d, c, gwID
}

// The same headline property on a plane that reads Postgres: the gateway is
// resolved through the finder and the caps from the polled copy, so a request
// costs no Redis command on either client and no per-request caps query.
func TestRateLimit_PostgresPlaneProxyForwardMakesZeroRedisCalls(t *testing.T) {
	d, c, gw := postgresPlane(t, "proxy", 5)

	var tooMany, forwarded int
	if err := c.Invoke(func(fwd appproxy.Forwarder) {
		for i := 0; i < 30; i++ {
			res, err := fwd.Forward(context.Background(), appproxy.ForwardInput{
				GatewayID: gw, Consumer: routable(gw), Request: &infracontext.RequestContext{},
			})
			if err == nil && res != nil && res.StatusCode == http.StatusTooManyRequests {
				tooMany++
			} else {
				forwarded++
			}
		}
	}); err != nil {
		t.Fatalf("resolve the forwarder: %v", err)
	}
	if forwarded != 5 || tooMany != 25 {
		t.Fatalf("admitted %d and refused %d, want 5 and 25: the tenant row (5/min) must be the cap", forwarded, tooMany)
	}
	if got := d.shared.n.Load(); got != 0 {
		t.Fatalf("the shared Redis client received %d commands on the forward path, want 0", got)
	}
	if got := d.sync.n.Load(); got != 0 {
		t.Fatalf("the sync client received %d commands on the forward path, want 0", got)
	}
	if err := d.meter.SyncNow(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if d.sync.n.Load() == 0 || d.shared.n.Load() != 0 {
		t.Fatalf("only the sync client may reach Redis: sync=%d shared=%d", d.sync.n.Load(), d.shared.n.Load())
	}
}

func TestRateLimit_PostgresPlaneMCPToolsCallMakesZeroRedisCalls(t *testing.T) {
	d, c, gw := postgresPlane(t, "mcp", 5)

	params, _ := json.Marshal(map[string]any{"name": "no_such_tool"})
	var limited, other int
	if err := c.Invoke(func(g *mcphttp.RPCGateway) {
		for i := 0; i < 30; i++ {
			_, err := g.Dispatch(context.Background(), routable(gw), "tools/call", params)
			var rpc interface{ ResolvedHTTPStatus() int }
			if errors.As(err, &rpc) && rpc.ResolvedHTTPStatus() == http.StatusTooManyRequests {
				limited++
			} else {
				other++
			}
		}
	}); err != nil {
		t.Fatalf("resolve the MCP gateway: %v", err)
	}
	if other != 5 || limited != 25 {
		t.Fatalf("admitted %d and refused %d, want 5 and 25", other, limited)
	}
	if got := d.shared.n.Load(); got != 0 {
		var seen []string
		d.shared.names.Range(func(k, _ any) bool { seen = append(seen, k.(string)); return true })
		t.Fatalf("the shared Redis client received %d commands on the tools/call path (%v), want 0", got, seen)
	}
	if got := d.sync.n.Load(); got != 0 {
		t.Fatalf("the sync client received %d commands on the tools/call path, want 0", got)
	}
	if err := d.meter.SyncNow(context.Background()); err != nil {
		t.Fatalf("sync: %v", err)
	}
	if d.sync.n.Load() == 0 || d.shared.n.Load() != 0 {
		t.Fatalf("only the sync client may reach Redis: sync=%d shared=%d", d.sync.n.Load(), d.shared.n.Load())
	}
}
