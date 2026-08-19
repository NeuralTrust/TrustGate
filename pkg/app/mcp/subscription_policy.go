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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const (
	// reauthBudgetFloor and reauthBudgetCeiling bound one re-authorization pass.
	// The ceiling stays below the fixed lifetime margin so a pass can never be in
	// flight when the lease deadline fires (RUN-1104 locked decision 3).
	reauthBudgetFloor   = 1 * time.Second
	reauthBudgetCeiling = 8 * time.Second

	surfaceDigestBytes = 16
)

// LeaseIdentity is everything a re-authorization pass needs, captured when the
// lease opened. It deliberately holds neither a Fiber context nor a consumer data
// snapshot: a frozen snapshot would make revocation permanently invisible.
type LeaseIdentity struct {
	Key       IsolationKey
	GatewayID ids.GatewayID
	AuthID    ids.AuthID
	Path      string
	Honoured  HonouredSet
}

// SurfaceSnapshot is one pass's per-kind surface digest. A kind the lease does
// not honour is the empty string, which is also how a kind with no baseline yet
// is reported.
type SurfaceSnapshot struct {
	Tools     string
	Prompts   string
	Resources string

	// Degraded marks the pass inconclusive: at least one bound registry was
	// skipped, so the composed surface is narrower than the real one.
	Degraded bool
}

// Digest is the digest recorded for the kind, or the empty string when the kind
// was not part of the pass.
func (s SurfaceSnapshot) Digest(kind NotificationKind) string {
	switch kind {
	case NotificationToolsListChanged:
		return s.Tools
	case NotificationPromptsListChanged:
		return s.Prompts
	case NotificationResourcesListChanged:
		return s.Resources
	default:
		return ""
	}
}

func (s *SurfaceSnapshot) set(kind NotificationKind, digest string) {
	switch kind {
	case NotificationToolsListChanged:
		s.Tools = digest
	case NotificationPromptsListChanged:
		s.Prompts = digest
	case NotificationResourcesListChanged:
		s.Resources = digest
	}
}

// Evaluation is one re-authorization pass's answer: the honoured kinds whose
// surface changed since the previous successful pass, and the snapshot the next
// pass must compare against.
type Evaluation struct {
	Changed  []NotificationKind
	Snapshot SurfaceSnapshot
}

//go:generate mockery --name=SubscriptionPolicy --dir=. --output=./mocks --filename=subscription_policy_mock.go --case=underscore --with-expecter

// SubscriptionPolicy decides what a live lease may still stream. Every emission
// is the product of one full pass: a refusal is reported as ErrSubscriptionRevoked
// and terminates the lease, and any other error leaves the previous snapshot in
// place rather than narrowing the stream.
type SubscriptionPolicy interface {
	Evaluate(ctx context.Context, id LeaseIdentity, prev SurfaceSnapshot) (Evaluation, error)
}

// UpstreamSubscriptionPolicy authorizes individual upstream events.
type UpstreamSubscriptionPolicy interface {
	SubscriptionPolicy
	AuthorizeEvent(
		ctx context.Context,
		identity SubscriptionIdentity,
		source SubscriptionSourceKey,
		kind NotificationKind,
	) (bool, error)
}

var _ SubscriptionPolicy = (*subscriptionPolicy)(nil)

type subscriptionPolicy struct {
	finder    appconsumer.DataFinder
	scoper    RoleScoper
	composer  Composer
	plugins   *PluginRunner
	creds     CredentialResolver
	sourceKey SubscriptionSourceKeyResolver
	flights   snapshotFlightGroup
}

// NewSubscriptionPolicyWithUpstream builds policy checks for watchdog and upstream events.
func NewSubscriptionPolicyWithUpstream(
	finder appconsumer.DataFinder,
	scoper RoleScoper,
	composer Composer,
	plugins *PluginRunner,
	creds CredentialResolver,
	connector SubscriptionConnector,
) UpstreamSubscriptionPolicy {
	policy := NewSubscriptionPolicy(finder, scoper, composer, plugins).(*subscriptionPolicy)
	policy.creds = creds
	policy.sourceKey, _ = connector.(SubscriptionSourceKeyResolver)
	return policy
}

// AuthorizeEvent freshly verifies every binding and source identity dimension.
func (p *subscriptionPolicy) AuthorizeEvent(
	ctx context.Context,
	identity SubscriptionIdentity,
	source SubscriptionSourceKey,
	kind NotificationKind,
) (bool, error) {
	if p.sourceKey == nil {
		return false, errors.New("mcp: upstream subscription policy is unavailable")
	}
	gatewayID, err := ids.Parse[ids.GatewayKind](identity.GatewayID)
	if err != nil {
		return false, fmt.Errorf("%w: invalid gateway binding", ErrSubscriptionRevoked)
	}
	data, err := p.finder.FindByGateway(ctx, gatewayID)
	if err != nil {
		return false, fmt.Errorf("mcp: refresh subscription consumer data: %w", err)
	}
	if data == nil || data.GatewayID.String() != identity.GatewayID {
		return false, fmt.Errorf("%w: gateway binding changed", ErrSubscriptionRevoked)
	}
	rc, ok := data.MatchPath(identity.Path)
	if !ok || rc == nil || rc.Consumer == nil ||
		rc.Consumer.ID.String() != identity.ConsumerID ||
		rc.Consumer.Type != consumerdomain.TypeMCP {
		return false, fmt.Errorf("%w: consumer binding changed", ErrSubscriptionRevoked)
	}
	if currentPrincipal := principalFingerprint(ctx); currentPrincipal != identity.PrincipalFingerprint {
		return false, fmt.Errorf("%w: principal binding changed", ErrSubscriptionRevoked)
	}
	currentAuthID := ""
	if authID, ok := appconsumer.AuthIDFromContext(ctx); ok {
		currentAuthID = authID.String()
	}
	if currentAuthID != identity.AuthID {
		return false, fmt.Errorf("%w: authentication binding changed", ErrSubscriptionRevoked)
	}
	if currentAuthID != "" {
		authID, parseErr := ids.Parse[ids.AuthKind](currentAuthID)
		if parseErr != nil ||
			(!consumerHasAuth(rc, authID) && authID != appauth.DefaultIdPAuthID()) {
			return false, fmt.Errorf("%w: authentication binding revoked", ErrSubscriptionRevoked)
		}
	}
	if rc.Consumer.ProtocolAcceptance() == consumerdomain.ProtocolAcceptanceLegacyOnly {
		return false, fmt.Errorf("%w: consumer protocol binding changed", ErrSubscriptionRevoked)
	}
	scoped, err := p.scoper.Scope(ctx, rc, data)
	if err != nil {
		if errors.Is(err, ErrNoRoleAccess) {
			return false, fmt.Errorf("%w: role binding revoked", ErrSubscriptionRevoked)
		}
		return false, fmt.Errorf("mcp: refresh subscription role scope: %w", err)
	}
	if scoped == nil || scoped.Consumer == nil ||
		SurfaceConfigFingerprint(scoped) != identity.RoleScopeFingerprint {
		return false, fmt.Errorf("%w: role scope binding changed", ErrSubscriptionRevoked)
	}
	registryID, err := ids.Parse[ids.RegistryKind](identity.RegistryID)
	if err != nil {
		return false, fmt.Errorf("%w: invalid registry binding", ErrSubscriptionRevoked)
	}
	registry := subscriptionRegistryByID(scoped, registryID)
	if registry == nil || !eligibleSubscriptionRegistry(registry) {
		return false, fmt.Errorf("%w: registry binding changed", ErrSubscriptionRevoked)
	}
	if !registryRequestedKinds(scoped, registry, NewHonouredSet(kind)).Has(kind) {
		return false, fmt.Errorf("%w: notification kind is no longer authorized", ErrSubscriptionRevoked)
	}
	target := targetFor(ctx, scoped, registry)
	if p.creds != nil {
		if err := p.creds.Apply(ctx, scoped, registry, &target); err != nil {
			return false, fmt.Errorf("mcp: refresh subscription credentials: %w", err)
		}
	}
	currentKey, err := p.sourceKey.SourceKey(target, source.Capabilities)
	if err != nil {
		return false, fmt.Errorf("mcp: derive subscription source identity: %w", err)
	}
	if currentKey != source || !source.Capabilities.HonouredSet().Has(kind) {
		return false, ErrSubscriptionSourceChanged
	}
	return true, nil
}

func subscriptionRegistryByID(
	rc *appconsumer.RoutableConsumer,
	id ids.RegistryID,
) *registrydomain.Registry {
	for _, registry := range rc.Registries {
		if registry != nil && registry.ID == id {
			return registry
		}
	}
	return nil
}

// NewSubscriptionPolicy builds the re-authorization pass a bounded lease ticks on.
func NewSubscriptionPolicy(
	finder appconsumer.DataFinder,
	scoper RoleScoper,
	composer Composer,
	plugins ...*PluginRunner,
) SubscriptionPolicy {
	var pluginRunner *PluginRunner
	if len(plugins) > 0 {
		pluginRunner = plugins[0]
	}
	return &subscriptionPolicy{
		finder:   finder,
		scoper:   scoper,
		composer: composer,
		plugins:  pluginRunner,
		flights:  snapshotFlightGroup{calls: make(map[reauthFlightKey]*snapshotFlight)},
	}
}

// Evaluate re-runs the whole authorization prologue against freshly resolved
// consumer data and re-composes every honoured kind. Reasons never carry the
// consumer slug, the principal, or any other tenant-identifying text.
func (p *subscriptionPolicy) Evaluate(
	ctx context.Context,
	id LeaseIdentity,
	prev SurfaceSnapshot,
) (Evaluation, error) {
	computed, err := p.flights.Do(ctx, reauthKey(id), func(workCtx context.Context) (surfaceComputation, error) {
		return p.compute(workCtx, id)
	})
	if err != nil {
		return Evaluation{Snapshot: prev}, err
	}
	if computed.degraded {
		prev.Degraded = true
		return Evaluation{Snapshot: prev}, nil
	}
	return Evaluation{
		Changed:  changedKinds(id.Honoured, prev, computed.snapshot),
		Snapshot: computed.snapshot,
	}, nil
}

func (p *subscriptionPolicy) compute(
	ctx context.Context,
	id LeaseIdentity,
) (surfaceComputation, error) {
	scoped, err := p.authorize(ctx, id)
	if err != nil {
		return surfaceComputation{}, err
	}

	statsCtx, stats := withCompositionStats(ctx)
	next := SurfaceSnapshot{}
	for _, kind := range id.Honoured.Kinds() {
		digest, err := p.digest(statsCtx, scoped, kind)
		if err != nil {
			return surfaceComputation{}, err
		}
		next.set(kind, digest)
	}
	if stats.Degraded() {
		return surfaceComputation{degraded: true}, nil
	}
	return surfaceComputation{snapshot: next}, nil
}

// authorize repeats the northbound prologue without any transport dependency and
// in the same order, so a lease can never outlive the request that opened it.
func (p *subscriptionPolicy) authorize(
	ctx context.Context,
	id LeaseIdentity,
) (*appconsumer.RoutableConsumer, error) {
	data, err := p.finder.FindByGateway(ctx, id.GatewayID)
	if err != nil {
		return nil, fmt.Errorf("mcp: resolve consumer data: %w", err)
	}
	rc, ok := data.MatchPath(id.Path)
	if !ok || rc == nil || rc.Consumer == nil {
		return nil, fmt.Errorf("%w: no virtual MCP configured for this path", ErrSubscriptionRevoked)
	}
	if rc.Consumer.Type != consumerdomain.TypeMCP {
		return nil, fmt.Errorf("%w: consumer is not an MCP consumer", ErrSubscriptionRevoked)
	}
	if !consumerHasAuth(rc, id.AuthID) && id.AuthID != appauth.DefaultIdPAuthID() {
		return nil, fmt.Errorf("%w: credential no longer allowed for this consumer", ErrSubscriptionRevoked)
	}
	if rc.Consumer.ProtocolAcceptance() == consumerdomain.ProtocolAcceptanceLegacyOnly {
		return nil, fmt.Errorf("%w: consumer accepts the legacy protocol only", ErrSubscriptionRevoked)
	}
	scoped, err := p.scoper.Scope(ctx, rc, data)
	if err != nil {
		if errors.Is(err, ErrNoRoleAccess) {
			return nil, fmt.Errorf("%w: %w", ErrSubscriptionRevoked, err)
		}
		return nil, fmt.Errorf("mcp: re-apply role scope: %w", err)
	}
	if SurfaceConfigFingerprint(scoped) != id.Key.RoleScope {
		return nil, fmt.Errorf("%w: surface configuration changed", ErrSubscriptionRevoked)
	}
	return scoped, nil
}

// digest composes one kind exactly as a client request would and hashes the
// exposed result. Resource templates fold into the resources digest: a template
// edit is a resource-surface change with no notification of its own (RUN-1104
// locked decision 1).
func (p *subscriptionPolicy) digest(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	kind NotificationKind,
) (string, error) {
	switch kind {
	case NotificationToolsListChanged:
		tools, err := p.composer.ListTools(ctx, rc)
		if err != nil {
			return "", fmt.Errorf("mcp: compose tools: %w", err)
		}
		if err := p.plugins.PreResponseToolsDiscovery(ctx, rc, tools); err != nil {
			return "", fmt.Errorf("%w: tools discovery denied by policy: %w", ErrSubscriptionRevoked, err)
		}
		encoded, err := encodeSurface(tools, func(t Tool) string { return t.Name })
		if err != nil {
			return "", err
		}
		return digestOf(encoded), nil
	case NotificationPromptsListChanged:
		prompts, err := p.composer.ListPrompts(ctx, rc)
		if err != nil {
			return "", fmt.Errorf("mcp: compose prompts: %w", err)
		}
		encoded, err := encodeSurface(prompts, func(pr Prompt) string { return pr.Name })
		if err != nil {
			return "", err
		}
		return digestOf(encoded), nil
	case NotificationResourcesListChanged:
		resources, err := p.composer.ListResources(ctx, rc)
		if err != nil {
			return "", fmt.Errorf("mcp: compose resources: %w", err)
		}
		templates, err := p.composer.ListResourceTemplates(ctx, rc)
		if err != nil {
			return "", fmt.Errorf("mcp: compose resource templates: %w", err)
		}
		encodedResources, err := encodeSurface(resources, func(r Resource) string { return r.Name + "\x00" + r.URI })
		if err != nil {
			return "", err
		}
		encodedTemplates, err := encodeSurface(templates, func(t ResourceTemplate) string {
			return t.Name + "\x00" + t.URITemplate
		})
		if err != nil {
			return "", err
		}
		return digestOf(encodedResources, encodedTemplates), nil
	default:
		return "", fmt.Errorf("mcp: unstreamable notification kind %q", kind)
	}
}

// encodeSurface renders one kind's exposed surface to bytes that depend only on
// its content. The primitives marshal a map envelope and encoding/json sorts map
// keys, so identical upstream bytes always produce identical output (RUN-1104 D5).
func encodeSurface[T any](items []T, key func(T) string) ([]byte, error) {
	sorted := make([]T, len(items))
	copy(sorted, items)
	sort.SliceStable(sorted, func(i, j int) bool { return key(sorted[i]) < key(sorted[j]) })
	encoded, err := json.Marshal(sorted)
	if err != nil {
		return nil, fmt.Errorf("mcp: encode composed surface: %w", err)
	}
	return encoded, nil
}

func digestOf(parts ...[]byte) string {
	sum := sha256.New()
	for _, part := range parts {
		sum.Write(part)
		sum.Write([]byte{0})
	}
	return hex.EncodeToString(sum.Sum(nil)[:surfaceDigestBytes])
}

type surfaceComputation struct {
	snapshot SurfaceSnapshot
	degraded bool
}

type reauthFlightKey struct {
	gatewayID  string
	consumerID string
	principal  string
	authID     string
	roleScope  string
	path       string
	tools      bool
	prompts    bool
	resources  bool
}

func reauthKey(id LeaseIdentity) reauthFlightKey {
	return reauthFlightKey{
		gatewayID:  id.GatewayID.String(),
		consumerID: id.Key.ConsumerID,
		principal:  id.Key.Principal,
		authID:     id.AuthID.String(),
		roleScope:  id.Key.RoleScope,
		path:       id.Path,
		tools:      id.Honoured.Has(NotificationToolsListChanged),
		prompts:    id.Honoured.Has(NotificationPromptsListChanged),
		resources:  id.Honoured.Has(NotificationResourcesListChanged),
	}
}

type snapshotFlight struct {
	done      chan struct{}
	result    surfaceComputation
	err       error
	waiters   int
	abandoned bool
	cancel    context.CancelFunc
}

type snapshotFlightGroup struct {
	mu    sync.Mutex
	calls map[reauthFlightKey]*snapshotFlight
}

func (g *snapshotFlightGroup) Do(
	ctx context.Context,
	key reauthFlightKey,
	fn func(context.Context) (surfaceComputation, error),
) (surfaceComputation, error) {
	if err := ctx.Err(); err != nil {
		return surfaceComputation{}, err
	}

	g.mu.Lock()
	call, ok := g.calls[key]
	if ok && !call.abandoned {
		call.waiters++
		g.mu.Unlock()
		return g.wait(ctx, key, call)
	}

	workCtx, cancel := detachedBoundedContext(ctx)
	call = &snapshotFlight{done: make(chan struct{}), waiters: 1, cancel: cancel}
	g.calls[key] = call
	g.mu.Unlock()

	go func() {
		call.result, call.err = fn(workCtx)
		g.mu.Lock()
		if g.calls[key] == call {
			delete(g.calls, key)
		}
		close(call.done)
		g.mu.Unlock()
		cancel()
	}()

	return g.wait(ctx, key, call)
}

func (g *snapshotFlightGroup) wait(
	ctx context.Context,
	key reauthFlightKey,
	call *snapshotFlight,
) (surfaceComputation, error) {
	select {
	case <-call.done:
		return call.result, call.err
	case <-ctx.Done():
		waitForStop := false
		g.mu.Lock()
		if g.calls[key] == call {
			call.waiters--
			if call.waiters == 0 {
				call.abandoned = true
				call.cancel()
				waitForStop = true
			}
		}
		g.mu.Unlock()
		if waitForStop {
			<-call.done
		}
		return surfaceComputation{}, ctx.Err()
	}
}

func detachedBoundedContext(ctx context.Context) (context.Context, context.CancelFunc) {
	base := context.WithoutCancel(ctx)
	if deadline, ok := ctx.Deadline(); ok {
		return context.WithDeadline(base, deadline)
	}
	return context.WithCancel(base)
}

// changedKinds reports the honoured kinds whose digest moved. A kind with no
// previous digest establishes its baseline instead of announcing a change, so a
// lease's first pass is silent.
func changedKinds(honoured HonouredSet, prev, next SurfaceSnapshot) []NotificationKind {
	var changed []NotificationKind
	for _, kind := range honoured.Kinds() {
		before := prev.Digest(kind)
		if before == "" || before == next.Digest(kind) {
			continue
		}
		changed = append(changed, kind)
	}
	return changed
}

func consumerHasAuth(rc *appconsumer.RoutableConsumer, authID ids.AuthID) bool {
	for _, id := range rc.Consumer.AuthIDs {
		if id == authID {
			return true
		}
	}
	return false
}

// ReauthBudget bounds one re-authorization pass to half the shortest cadence the
// loop runs on, clamped to [1s, 8s]. Nothing in the discovery chain has a
// deadline of its own, so without this bound an unresponsive upstream would park
// the writer, stop keepalives, and let the write deadline sever the connection.
func ReauthBudget(reauth, keepalive time.Duration) time.Duration {
	shortest := reauth
	if keepalive > 0 && (shortest <= 0 || keepalive < shortest) {
		shortest = keepalive
	}
	budget := shortest / 2
	if budget < reauthBudgetFloor {
		return reauthBudgetFloor
	}
	if budget > reauthBudgetCeiling {
		return reauthBudgetCeiling
	}
	return budget
}
