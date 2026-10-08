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

package catalog

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/domain/bedrocknative"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const (
	sweepRegistries = 4
	sweepEntries    = 32
)

// BedrockResolverLimits bounds the resolver. The ARN of every call is the client's,
// so what a client can start, and what it can make the gateway remember, is
// capped: per registry, so one tenant cannot take every slot or evict another's
// models, and across all of them.
type BedrockResolverLimits struct {
	// MaxInFlight is the control plane calls in flight across every registry.
	MaxInFlight int
	// MaxPerRegistry is the calls one registry can have in flight.
	MaxPerRegistry int
	// MaxEntries is what is remembered for each registry, and the set of ARNs
	// already warned about.
	MaxEntries int
	// ResolvedTTL and UnresolvedTTL are how long an answer and a failure are kept.
	ResolvedTTL   time.Duration
	UnresolvedTTL time.Duration
	// LookupTimeout bounds one control plane call.
	LookupTimeout time.Duration
}

// DefaultBedrockResolverLimits are the limits the gateway runs with unless configured.
func DefaultBedrockResolverLimits() BedrockResolverLimits {
	d := config.DefaultBedrockNative()
	return BedrockResolverLimits{
		MaxInFlight:    d.ResolverMaxInFlight,
		MaxPerRegistry: d.ResolverMaxPerRegistry,
		MaxEntries:     d.ResolverCacheEntries,
		ResolvedTTL:    d.ResolverResolvedTTL,
		UnresolvedTTL:  d.ResolverUnresolvedTTL,
		LookupTimeout:  d.ResolverControlPlaneTimeout,
	}
}

// BedrockCredentials are the registry credentials a lookup is made with.
type BedrockCredentials struct {
	Region       string
	AccessKey    string
	SecretKey    string
	SessionToken string
	UseRole      bool
	RoleARN      string
}

// BedrockModelARNLookup asks the Bedrock control plane which model sits behind
// an application inference profile or provisioned throughput ARN. The resolver
// depends on this port, and the container adapts the infra client to it.
//
//go:generate mockery --name=BedrockModelARNLookup --dir=. --output=./mocks --filename=catalog_bedrock_model_arn_lookup_mock.go --case=underscore --with-expecter
type BedrockModelARNLookup interface {
	ResolveModelARN(ctx context.Context, creds BedrockCredentials, arn string) (string, error)
}

// BedrockModelResolver learns which model sits behind an opaque Bedrock ARN
// (an application inference profile or provisioned throughput) so a native call
// can be priced. It is never waited on: Lookup answers from the cache and, on a
// miss, starts the control plane call in the background, so the request that
// asked is not delayed by it and a failure never reaches it.
//
//go:generate mockery --name=BedrockModelResolver --dir=. --output=./mocks --filename=catalog_bedrock_model_resolver_mock.go --case=underscore --with-expecter
type BedrockModelResolver interface {
	// Lookup returns the model ID behind arn when it is already known. On a
	// miss it starts a background lookup with the registry's credentials and
	// returns false. The lookup keeps the values of ctx (the request's trace) and
	// not its cancellation.
	Lookup(ctx context.Context, reg *registrydomain.Registry, arn string) (string, bool)
	// Resolve is Lookup that waits for the lookup it started, or that another
	// call for the same ARN already started, for at most wait. It shares the
	// cache, the negative entries and the single flight, so concurrent first
	// calls make one control plane call, and a negative entry returns at once.
	Resolve(ctx context.Context, reg *registrydomain.Registry, arn string, wait time.Duration) (string, bool)
	// Close stops starting lookups and waits for those in flight, until ctx ends.
	Close(ctx context.Context) error
}

var errLookupSkipped = errors.New("bedrock model lookup skipped")

type resolvedModel struct {
	model   string
	expires time.Time
}

type bedrockModelResolver struct {
	lookup BedrockModelARNLookup
	logger *slog.Logger
	now    func() time.Time
	limits BedrockResolverLimits

	flights singleflight.Group
	slots   chan struct{}

	mu       sync.Mutex
	caches   map[string]*modelCache
	perReg   map[string]int
	warned   map[string]*list.Element
	warnedLR *list.List
	active   int
	closed   bool
	drained  chan struct{}
}

// modelCache is what is remembered for one registry. Each registry has its own,
// so one tenant's misses never evict another tenant's models; inside it the least
// recently used entry goes first, but a model that resolved outlives one that
// failed.
type modelCache struct {
	entries map[string]*list.Element
	order   *list.List
}

type cacheEntry struct {
	arn string
	resolvedModel
}

func newModelCache() *modelCache {
	return &modelCache{entries: map[string]*list.Element{}, order: list.New()}
}

func NewBedrockModelResolver(lookup BedrockModelARNLookup, logger *slog.Logger) BedrockModelResolver {
	return NewBedrockModelResolverWithLimits(lookup, logger, DefaultBedrockResolverLimits())
}

func NewBedrockModelResolverWithLimits(lookup BedrockModelARNLookup, logger *slog.Logger, limits BedrockResolverLimits) BedrockModelResolver {
	defaults := DefaultBedrockResolverLimits()
	if limits.MaxInFlight <= 0 {
		limits.MaxInFlight = defaults.MaxInFlight
	}
	if limits.MaxPerRegistry <= 0 {
		limits.MaxPerRegistry = defaults.MaxPerRegistry
	}
	if limits.MaxEntries <= 0 {
		limits.MaxEntries = defaults.MaxEntries
	}
	if limits.ResolvedTTL <= 0 {
		limits.ResolvedTTL = defaults.ResolvedTTL
	}
	if limits.UnresolvedTTL <= 0 {
		limits.UnresolvedTTL = defaults.UnresolvedTTL
	}
	if limits.LookupTimeout <= 0 {
		limits.LookupTimeout = defaults.LookupTimeout
	}
	return &bedrockModelResolver{
		lookup:   lookup,
		logger:   logger,
		now:      time.Now,
		limits:   limits,
		slots:    make(chan struct{}, limits.MaxInFlight),
		caches:   make(map[string]*modelCache),
		perReg:   make(map[string]int),
		warned:   make(map[string]*list.Element),
		warnedLR: list.New(),
	}
}

func (r *bedrockModelResolver) Lookup(ctx context.Context, reg *registrydomain.Registry, arn string) (string, bool) {
	model, ok, _ := r.begin(ctx, reg, arn)
	return model, ok
}

func (r *bedrockModelResolver) Resolve(
	ctx context.Context,
	reg *registrydomain.Registry,
	arn string,
	wait time.Duration,
) (string, bool) {
	model, ok, flight := r.begin(ctx, reg, arn)
	if ok || flight == nil {
		return model, ok
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case res := <-flight:
		model, _ := res.Val.(string)
		return model, res.Err == nil && model != ""
	case <-timer.C:
		return "", false
	case <-ctx.Done():
		return "", false
	}
}

func (r *bedrockModelResolver) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	if r.active == 0 {
		r.mu.Unlock()
		return nil
	}
	if r.drained == nil {
		r.drained = make(chan struct{})
	}
	drained := r.drained
	r.mu.Unlock()
	select {
	case <-drained:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (r *bedrockModelResolver) begin(ctx context.Context, reg *registrydomain.Registry, arn string) (string, bool, <-chan singleflight.Result) {
	if reg == nil || reg.Auth() == nil || reg.Auth().AWS == nil {
		return "", false, nil
	}
	parsed, ok := bedrocknative.ParseOpaqueBedrockARN(arn)
	if !ok {
		return "", false, nil
	}
	regID := reg.ID.String()

	r.mu.Lock()
	if e, hit := r.get(regID, arn); hit {
		r.mu.Unlock()
		return e.model, e.model != "", nil
	}
	closed := r.closed
	r.mu.Unlock()
	if closed {
		return "", false, nil
	}

	aws := reg.Auth().AWS
	creds := BedrockCredentials{
		Region: aws.Region, AccessKey: aws.AccessKeyID, SecretKey: aws.SecretAccessKey,
		SessionToken: aws.SessionToken, UseRole: aws.UseRole, RoleARN: aws.Role,
	}
	parent := context.WithoutCancel(ctx)
	flight := r.flights.DoChan(regID+"|"+arn, func() (any, error) {
		return r.fetch(parent, regID, arn, parsed, creds)
	})
	return "", false, flight
}

// acquire claims a lookup slot for the registry, or refuses: the resolver is
// closed, the registry already has its share in flight, or every slot is taken.
// A refused lookup is skipped and the model stays unpriced, as for any lookup
// that fails, rather than queueing work the client chose.
func (r *bedrockModelResolver) acquire(regID string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.perReg[regID] >= r.limits.MaxPerRegistry {
		return false
	}
	select {
	case r.slots <- struct{}{}:
		r.perReg[regID]++
		r.active++
		return true
	default:
		return false
	}
}

func (r *bedrockModelResolver) release(regID string) {
	r.mu.Lock()
	if r.perReg[regID]--; r.perReg[regID] <= 0 {
		delete(r.perReg, regID)
	}
	r.active--
	if r.closed && r.active == 0 && r.drained != nil {
		close(r.drained)
		r.drained = nil
	}
	<-r.slots
	r.mu.Unlock()
}

// callControlPlane runs the lookup on a goroutine nobody waits on, so a panic
// in the client would take the whole gateway down and leave the single flight
// entry, and every caller parked on it, behind. It becomes an error instead:
// fetch then stores a negative entry and releases the waiters as for any
// other failure.
func (r *bedrockModelResolver) callControlPlane(ctx context.Context, creds BedrockCredentials, arn string) (modelARN string, err error) {
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("control plane lookup panicked: %v", rec)
			if r.logger != nil {
				r.logger.Error("bedrock model resolver recovered from a panic", slog.Any("panic", rec))
			}
		}
	}()
	return r.lookup.ResolveModelARN(ctx, creds, arn)
}

func (r *bedrockModelResolver) fetch(
	parent context.Context,
	regID, arn string,
	parsed bedrocknative.BedrockARN,
	creds BedrockCredentials,
) (any, error) {
	if !r.acquire(regID) {
		return "", errLookupSkipped
	}
	defer r.release(regID)
	ctx, cancel := context.WithTimeout(parent, r.limits.LookupTimeout)
	defer cancel()
	model := ""
	modelARN, err := r.callControlPlane(ctx, creds, arn)
	if err == nil {
		if id, ok := bedrocknative.ModelIDFromModelARN(modelARN); ok {
			model = id
		}
	}

	ttl := r.limits.ResolvedTTL
	if model == "" {
		ttl = r.limits.UnresolvedTTL
	}
	r.mu.Lock()
	r.store(regID, arn, resolvedModel{model: model, expires: r.now().Add(ttl)})
	warn := model == "" && r.markWarned(regID+"|"+arn)
	r.mu.Unlock()
	if warn {
		r.warn(parsed, err)
	}
	return model, nil
}

func (r *bedrockModelResolver) markWarned(key string) bool {
	if el, seen := r.warned[key]; seen {
		r.warnedLR.MoveToFront(el)
		return false
	}
	if r.warnedLR.Len() >= r.limits.MaxEntries {
		oldest := r.warnedLR.Back()
		delete(r.warned, oldest.Value.(string))
		r.warnedLR.Remove(oldest)
	}
	r.warned[key] = r.warnedLR.PushFront(key)
	return true
}

func (r *bedrockModelResolver) warn(parsed bedrocknative.BedrockARN, err error) {
	if r.logger == nil {
		return
	}
	attrs := []any{
		slog.String("kind", parsed.Kind),
		slog.String("region", parsed.Region),
		slog.String("hint", "grant bedrock:GetInferenceProfile or bedrock:GetProvisionedModelThroughput to the registry credentials; usage is recorded without a cost until then"),
	}
	if err != nil {
		attrs = append(attrs, slog.String("error", err.Error()))
	}
	r.logger.Warn("bedrock model behind an opaque ARN could not be resolved", attrs...)
}

func (r *bedrockModelResolver) warnedSize() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.warned)
}

// get returns a live entry. An expired one is dropped on the way, and a registry
// left with no entries stops being tracked. The caller holds the lock.
func (r *bedrockModelResolver) get(regID, arn string) (resolvedModel, bool) {
	c := r.caches[regID]
	if c == nil {
		return resolvedModel{}, false
	}
	el, ok := c.entries[arn]
	if !ok {
		return resolvedModel{}, false
	}
	entry := el.Value.(*cacheEntry)
	if !r.now().Before(entry.expires) {
		r.drop(regID, c, el)
		return resolvedModel{}, false
	}
	c.order.MoveToFront(el)
	return entry.resolvedModel, true
}

func (r *bedrockModelResolver) drop(regID string, c *modelCache, el *list.Element) {
	c.remove(el)
	if len(c.entries) == 0 {
		delete(r.caches, regID)
	}
}

// store keeps one registry's cache bounded. A full cache drops expired entries
// first, then the least recently used entry that failed, and only then the least
// recently used one that resolved: the models a tenant pays for are what is worth
// keeping, and a flood of failed lookups must not push them out. The caller holds
// the lock.
func (r *bedrockModelResolver) store(regID, arn string, e resolvedModel) {
	defer r.sweep()
	c := r.caches[regID]
	if c == nil {
		c = newModelCache()
		r.caches[regID] = c
	}
	if el, ok := c.entries[arn]; ok {
		el.Value.(*cacheEntry).resolvedModel = e
		c.order.MoveToFront(el)
		return
	}
	if len(c.entries) >= r.limits.MaxEntries {
		r.evict(c)
	}
	c.entries[arn] = c.order.PushFront(&cacheEntry{arn: arn, resolvedModel: e})
}

// sweep drops expired entries from a few registries' least recently used end, so
// a registry nobody asks about again does not keep its entries for the life of
// the process. The work per call is bounded. The caller holds the lock.
func (r *bedrockModelResolver) sweep() {
	now := r.now()
	visited := 0
	for regID, c := range r.caches {
		if visited++; visited > sweepRegistries {
			return
		}
		scanned := 0
		for el := c.order.Back(); el != nil && scanned < sweepEntries; scanned++ {
			prev := el.Prev()
			if !now.Before(el.Value.(*cacheEntry).expires) {
				c.remove(el)
			}
			el = prev
		}
		if len(c.entries) == 0 {
			delete(r.caches, regID)
		}
	}
}

func (r *bedrockModelResolver) evict(c *modelCache) {
	now := r.now()
	var failed, any *list.Element
	for el := c.order.Back(); el != nil; el = el.Prev() {
		entry := el.Value.(*cacheEntry)
		if !now.Before(entry.expires) {
			c.remove(el)
			return
		}
		if failed == nil && entry.model == "" {
			failed = el
		}
		if any == nil {
			any = el
		}
	}
	if failed != nil {
		c.remove(failed)
		return
	}
	if any != nil {
		c.remove(any)
	}
}

func (c *modelCache) remove(el *list.Element) {
	delete(c.entries, el.Value.(*cacheEntry).arn)
	c.order.Remove(el)
}
