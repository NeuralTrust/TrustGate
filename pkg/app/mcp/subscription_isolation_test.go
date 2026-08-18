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

package mcp

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/stretchr/testify/require"
)

func isolationConsumer(
	slug string,
	authID ids.AuthID,
	toolkit consumerdomain.Toolkit,
	regs ...*registrydomain.Registry,
) *consumerdomain.Consumer {
	registryIDs := make([]ids.RegistryID, 0, len(regs))
	for _, reg := range regs {
		registryIDs = append(registryIDs, reg.ID)
	}
	consumer := &consumerdomain.Consumer{
		ID:          ids.New[ids.ConsumerKind](),
		Type:        consumerdomain.TypeMCP,
		Slug:        slug,
		Active:      true,
		AuthIDs:     []ids.AuthID{authID},
		RegistryIDs: registryIDs,
	}
	if toolkit != nil {
		consumer.MCP = &consumerdomain.MCPPolicy{Toolkit: toolkit, FailMode: consumerdomain.FailModeOpen}
	}
	return consumer
}

// isolationData puts every consumer on one gateway, which is the arrangement
// that makes a leak possible in the first place: separate gateways would be
// isolated by construction.
func isolationData(bindings map[*consumerdomain.Consumer][]*registrydomain.Registry) *appconsumer.Data {
	routables := make([]appconsumer.RoutableConsumer, 0, len(bindings))
	for consumer, regs := range bindings {
		routables = append(routables, appconsumer.RoutableConsumer{Consumer: consumer, Registries: regs})
	}
	return appconsumer.NewData(ids.New[ids.GatewayKind](), routables)
}

func isolationIdentity(authID ids.AuthID, data *appconsumer.Data, slug string, honoured ...NotificationKind) LeaseIdentity {
	rc, _ := data.MatchPath(appconsumer.MCPPath(slug))
	return LeaseIdentity{
		Key: IsolationKey{
			GatewayID:  data.GatewayID.String(),
			ConsumerID: rc.Consumer.ID.String(),
			Principal:  authID.String(),
			RoleScope:  SurfaceConfigFingerprint(rc),
		},
		GatewayID: data.GatewayID,
		AuthID:    authID,
		Path:      appconsumer.MCPPath(slug),
		Honoured:  NewHonouredSet(honoured...),
	}
}

// Two tenants may legitimately expose the same resource URI. The digest is taken
// over the surface each consumer is actually served, so a URI they share must
// neither make their snapshots equal nor let one tenant's edit announce a change
// on the other's lease.
func TestSubscriptionIsolation_SharedResourceURIStaysInsideItsConsumer(t *testing.T) {
	t.Parallel()
	const (
		urlA      = "https://a.example.com/mcp"
		urlB      = "https://b.example.com/mcp"
		sharedURI = "db://orders"
	)

	regA := mcpRegistry(t, "a", urlA)
	regB := mcpRegistry(t, "b", urlB)
	authID := ids.New[ids.AuthKind]()
	consumerA := isolationConsumer("tenant-a", authID, nil, regA)
	consumerB := isolationConsumer("tenant-b", authID, nil, regB)
	data := isolationData(map[*consumerdomain.Consumer][]*registrydomain.Registry{
		consumerA: {regA},
		consumerB: {regB},
	})

	upstreamA := &fakeUpstream{resources: []Resource{{Name: "orders", URI: sharedURI}}}
	upstreamB := &fakeUpstream{resources: []Resource{{Name: "orders", URI: sharedURI}}}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{urlA: upstreamA, urlB: upstreamB}}
	policy := NewSubscriptionPolicy(
		&stubDataFinder{data: data},
		passthroughScoper{},
		NewComposer(dialer, nil, uncachedDiscovery{}, slog.New(slog.DiscardHandler)),
	)

	idA := isolationIdentity(authID, data, "tenant-a", NotificationResourcesListChanged)
	idB := isolationIdentity(authID, data, "tenant-b", NotificationResourcesListChanged)

	require.NotEqual(t, idA.Key, idB.Key, "the shared URI collapsed two tenants onto one isolation key")

	baseA, err := policy.Evaluate(context.Background(), idA, SurfaceSnapshot{})
	require.NoError(t, err)
	baseB, err := policy.Evaluate(context.Background(), idB, SurfaceSnapshot{})
	require.NoError(t, err)
	require.Empty(t, baseA.Changed)
	require.Empty(t, baseB.Changed)

	upstreamB.resources = []Resource{
		{Name: "orders", URI: sharedURI},
		{Name: "invoices", URI: "db://invoices"},
	}

	nextA, err := policy.Evaluate(context.Background(), idA, baseA.Snapshot)
	require.NoError(t, err)
	require.Empty(t, nextA.Changed, "tenant B's edit announced a change on tenant A's lease")
	require.Equal(t, baseA.Snapshot, nextA.Snapshot)

	nextB, err := policy.Evaluate(context.Background(), idB, baseB.Snapshot)
	require.NoError(t, err)
	require.Equal(t, []NotificationKind{NotificationResourcesListChanged}, nextB.Changed)
}

// Two principals share one consumer but not one surface: the role scope narrows
// what each is served. A pass runs under the principal that opened the lease, so
// the other principal's surface must be invisible to it in both directions —
// neither in its digest nor as a change it announces.
func TestSubscriptionIsolation_DisjointRoleScopesDoNotCrossPrincipals(t *testing.T) {
	t.Parallel()
	const (
		urlOps  = "https://ops.example.com/mcp"
		urlRead = "https://read.example.com/mcp"
	)

	regOps := mcpRegistry(t, "ops", urlOps)
	regRead := mcpRegistry(t, "read", urlRead)
	authID := ids.New[ids.AuthKind]()
	consumer := isolationConsumer("tenant-a", authID, nil, regOps, regRead)
	data := isolationData(map[*consumerdomain.Consumer][]*registrydomain.Registry{
		consumer: {regOps, regRead},
	})

	opsUpstream := &fakeUpstream{tools: tools("deploy")}
	readUpstream := &fakeUpstream{tools: tools("search")}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{urlOps: opsUpstream, urlRead: readUpstream}}
	scoper := principalScoper{registries: map[string][]*registrydomain.Registry{
		"operator": {regOps},
		"reader":   {regRead},
	}}
	policy := NewSubscriptionPolicy(
		&stubDataFinder{data: data},
		scoper,
		NewComposer(dialer, nil, uncachedDiscovery{}, slog.New(slog.DiscardHandler)),
	)

	operator := principalContext("operator")
	reader := principalContext("reader")
	idOperator := scopedIdentity(t, scoper, operator, authID, data, "tenant-a")
	idReader := scopedIdentity(t, scoper, reader, authID, data, "tenant-a")

	require.NotEqual(t, idOperator.Key.RoleScope, idReader.Key.RoleScope,
		"two disjoint role scopes collapsed onto one isolation key")

	baseOperator, err := policy.Evaluate(operator, idOperator, SurfaceSnapshot{})
	require.NoError(t, err)
	baseReader, err := policy.Evaluate(reader, idReader, SurfaceSnapshot{})
	require.NoError(t, err)
	require.NotEqual(t, baseOperator.Snapshot.Tools, baseReader.Snapshot.Tools)

	readUpstream.tools = tools("search", "search_v2")

	nextOperator, err := policy.Evaluate(operator, idOperator, baseOperator.Snapshot)
	require.NoError(t, err)
	require.Empty(t, nextOperator.Changed, "a change outside the principal's role scope announced itself")

	nextReader, err := policy.Evaluate(reader, idReader, baseReader.Snapshot)
	require.NoError(t, err)
	require.Equal(t, []NotificationKind{NotificationToolsListChanged}, nextReader.Changed)
}

// The discovery cache is keyed by registry and kind, not by consumer, so two
// consumers bound to the same registry read the same upstream bytes. That is
// only safe because the toolkit is applied per consumer after the read.
func TestSubscriptionIsolation_SharedDiscoveryCacheKeepsPerConsumerSurfaces(t *testing.T) {
	t.Parallel()
	const url = "https://shared.example.com/mcp"

	reg := mcpRegistry(t, "shared", url)
	authID := ids.New[ids.AuthKind]()
	consumerA := isolationConsumer("tenant-a", authID,
		consumerdomain.Toolkit{{RegistryID: reg.ID, Tool: "search"}}, reg)
	consumerB := isolationConsumer("tenant-b", authID,
		consumerdomain.Toolkit{{RegistryID: reg.ID, Tool: "deploy"}}, reg)
	data := isolationData(map[*consumerdomain.Consumer][]*registrydomain.Registry{
		consumerA: {reg},
		consumerB: {reg},
	})

	upstream := &fakeUpstream{tools: tools("search", "deploy")}
	dialer := newCountingDialer(func(string) (Upstream, error) { return upstream, nil })
	composer := newTestComposer(dialer)
	policy := NewSubscriptionPolicy(&stubDataFinder{data: data}, passthroughScoper{}, composer)

	idA := isolationIdentity(authID, data, "tenant-a", NotificationToolsListChanged)
	idB := isolationIdentity(authID, data, "tenant-b", NotificationToolsListChanged)

	evalA, err := policy.Evaluate(context.Background(), idA, SurfaceSnapshot{})
	require.NoError(t, err)
	evalB, err := policy.Evaluate(context.Background(), idB, SurfaceSnapshot{})
	require.NoError(t, err)

	require.Equal(t, 1, dialer.count(url), "the shared cache entry was not reused")
	require.NotEqual(t, evalA.Snapshot.Tools, evalB.Snapshot.Tools,
		"both tenants digested the cached upstream surface instead of their own")

	rcA, ok := data.MatchPath(appconsumer.MCPPath("tenant-a"))
	require.True(t, ok)
	rcB, ok := data.MatchPath(appconsumer.MCPPath("tenant-b"))
	require.True(t, ok)

	listedA, err := composer.ListTools(context.Background(), rcA)
	require.NoError(t, err)
	require.Equal(t, []string{"search"}, toolNames(listedA))

	listedB, err := composer.ListTools(context.Background(), rcB)
	require.NoError(t, err)
	require.Equal(t, []string{"deploy"}, toolNames(listedB))
}

// A re-authorization pass is bounded by ReauthBudget, so it is the shortest-lived
// caller the discovery cache ever has. Its budget expiring is a fact about that
// pass and must not be recorded as an upstream failure other requests read back
// (RUN-1104: lease re-auth shares the discovery singleflight with live traffic).
func TestSubscriptionIsolation_ExpiredReauthBudgetDoesNotPoisonLiveRequests(t *testing.T) {
	t.Parallel()
	const url = "https://slow.example.com/mcp"

	reg := mcpRegistry(t, "slow", url)
	authID := ids.New[ids.AuthKind]()
	consumer := isolationConsumer("tenant-a", authID, nil, reg)
	data := isolationData(map[*consumerdomain.Consumer][]*registrydomain.Registry{consumer: {reg}})

	gate := newDialGate(&fakeUpstream{tools: tools("search")}, url)
	composer := newTestComposer(gate)
	policy := NewSubscriptionPolicy(&stubDataFinder{data: data}, passthroughScoper{}, composer)
	id := isolationIdentity(authID, data, "tenant-a", NotificationToolsListChanged)

	budgeted, cancel := context.WithCancel(context.Background())
	passed := make(chan error, 1)
	go func() {
		_, err := policy.Evaluate(budgeted, id, SurfaceSnapshot{})
		passed <- err
	}()

	<-gate.dialing
	cancel()
	require.ErrorIs(t, <-passed, context.Canceled)

	gate.release()

	rc, ok := data.MatchPath(appconsumer.MCPPath("tenant-a"))
	require.True(t, ok)
	listed, err := composer.ListTools(context.Background(), rc)
	require.NoError(t, err, "a live request inherited the re-auth pass's cancellation")
	require.Equal(t, []string{"search"}, toolNames(listed))
}

// A live request that joins the flight a lease is leading does inherit that
// lease's cancellation, because singleflight shares one outcome. What must not
// happen is that the coupling outlives the flight: the next request has to reach
// the upstream rather than read the lease's budget back out of the cache.
func TestSubscriptionIsolation_ReauthCancellationDoesNotOutliveItsFlight(t *testing.T) {
	t.Parallel()
	const url = "https://slow.example.com/mcp"

	reg := mcpRegistry(t, "slow", url)
	authID := ids.New[ids.AuthKind]()
	consumer := isolationConsumer("tenant-a", authID, nil, reg)
	data := isolationData(map[*consumerdomain.Consumer][]*registrydomain.Registry{consumer: {reg}})

	gate := newDialGate(&fakeUpstream{tools: tools("search")}, url)
	composer := newTestComposer(gate)
	policy := NewSubscriptionPolicy(&stubDataFinder{data: data}, passthroughScoper{}, composer)
	id := isolationIdentity(authID, data, "tenant-a", NotificationToolsListChanged)
	rc, ok := data.MatchPath(appconsumer.MCPPath("tenant-a"))
	require.True(t, ok)

	budgeted, cancel := context.WithCancel(context.Background())
	passed := make(chan error, 1)
	go func() {
		_, err := policy.Evaluate(budgeted, id, SurfaceSnapshot{})
		passed <- err
	}()
	<-gate.dialing

	joined := make(chan error, 1)
	go func() {
		_, err := composer.ListTools(context.Background(), rc)
		joined <- err
	}()

	cancel()
	require.ErrorIs(t, <-passed, context.Canceled)

	gate.release()
	<-joined
	listed, err := composer.ListTools(context.Background(), rc)
	require.NoError(t, err, "the lease's cancellation was still cached against the registry")
	require.Equal(t, []string{"search"}, toolNames(listed))
}

// Under load the lease's pass and live requests collapse onto the same discovery
// key, so this is where a shared flight would show up: as a live request failing
// for a reason that belongs to a lease.
func TestSubscriptionIsolation_ConcurrentReauthAndLiveRequestsStayIndependent(t *testing.T) {
	t.Parallel()
	const (
		url    = "https://busy.example.com/mcp"
		rounds = 64
	)

	reg := mcpRegistry(t, "busy", url)
	authID := ids.New[ids.AuthKind]()
	consumer := isolationConsumer("tenant-a", authID, nil, reg)
	data := isolationData(map[*consumerdomain.Consumer][]*registrydomain.Registry{consumer: {reg}})

	upstream := &fakeUpstream{tools: tools("search")}
	dialer := newCountingDialer(func(string) (Upstream, error) { return upstream, nil })
	composer := newTestComposer(dialer)
	policy := NewSubscriptionPolicy(&stubDataFinder{data: data}, passthroughScoper{}, composer)
	id := isolationIdentity(authID, data, "tenant-a", NotificationToolsListChanged)
	rc, ok := data.MatchPath(appconsumer.MCPPath("tenant-a"))
	require.True(t, ok)

	var (
		wg        sync.WaitGroup
		liveFails atomic.Int64
	)
	for i := 0; i < rounds; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			budgeted, cancel := context.WithTimeout(context.Background(), time.Microsecond)
			defer cancel()
			_, _ = policy.Evaluate(budgeted, id, SurfaceSnapshot{})
		}()
		go func() {
			defer wg.Done()
			if _, err := composer.ListTools(context.Background(), rc); err != nil {
				liveFails.Add(1)
			}
		}()
	}
	wg.Wait()

	listed, err := composer.ListTools(context.Background(), rc)
	require.NoError(t, err, "a lease's expired budget was still cached against the registry")
	require.Equal(t, []string{"search"}, toolNames(listed))
	require.Zero(t, liveFails.Load(), "live requests inherited a re-auth pass's deadline")
}

// principalScoper narrows the consumer to the registries the acting principal's
// role grants, which is the shape RoleScoper produces for an OIDC consumer.
type principalScoper struct {
	registries map[string][]*registrydomain.Registry
}

func (s principalScoper) Scope(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	_ *appconsumer.Data,
) (*appconsumer.RoutableConsumer, error) {
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil {
		return nil, ErrNoRoleAccess
	}
	granted, ok := s.registries[principal.Subject]
	if !ok {
		return nil, ErrNoRoleAccess
	}
	scoped := *rc
	scoped.Registries = granted
	return &scoped, nil
}

func principalContext(subject string) context.Context {
	return identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: subject,
		Issuer:  "https://idp.example.com",
	})
}

// scopedIdentity captures the lease identity the handler would have derived for
// this principal, which is the scoped view rather than the consumer's whole one.
func scopedIdentity(
	t *testing.T,
	scoper RoleScoper,
	ctx context.Context,
	authID ids.AuthID,
	data *appconsumer.Data,
	slug string,
) LeaseIdentity {
	t.Helper()
	rc, ok := data.MatchPath(appconsumer.MCPPath(slug))
	require.True(t, ok)
	scoped, err := scoper.Scope(ctx, rc, data)
	require.NoError(t, err)
	return LeaseIdentity{
		Key:       NewIsolationKey(ctx, data.GatewayID.String(), scoped),
		GatewayID: data.GatewayID,
		AuthID:    authID,
		Path:      appconsumer.MCPPath(slug),
		Honoured:  NewHonouredSet(NotificationToolsListChanged),
	}
}

// uncachedDiscovery keeps a case that mutates an upstream between passes honest:
// with a real cache the second pass would answer from the first one's bytes.
type uncachedDiscovery struct{}

func (uncachedDiscovery) Get(string) (any, bool) { return nil, false }
func (uncachedDiscovery) Set(string, any)        {}

// dialGate holds the first dial open until the test releases it, which is how a
// pass is made to run out of budget mid-discovery without a real sleep.
type dialGate struct {
	url      string
	upstream *fakeUpstream
	dialing  chan struct{}
	open     chan struct{}
	once     sync.Once
}

func newDialGate(upstream *fakeUpstream, url string) *dialGate {
	return &dialGate{
		url:      url,
		upstream: upstream,
		dialing:  make(chan struct{}, 1),
		open:     make(chan struct{}),
	}
}

func (g *dialGate) release() { g.once.Do(func() { close(g.open) }) }

func (g *dialGate) Connect(ctx context.Context, target Target) (Upstream, error) {
	if target.URL != g.url {
		return nil, ErrUpstreamUnavailable
	}
	select {
	case g.dialing <- struct{}{}:
	default:
	}
	select {
	case <-g.open:
		return g.upstream, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
