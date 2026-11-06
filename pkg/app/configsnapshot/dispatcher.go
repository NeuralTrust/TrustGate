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

package configsnapshot

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

const component = "configsnapshot"

const (
	defaultDebounce  = 250 * time.Millisecond
	defaultBackstop  = 5 * time.Minute
	defaultRetention = 24 * time.Hour
	defaultMaxRows   = 10000
)

// SnapshotCompiler compiles the current State-of-the-World from the live config.
type SnapshotCompiler interface {
	Compile(ctx context.Context) (*readmodel.Snapshot, error)
}

// PartitionedCompiler compiles the global snapshot, tenant-only scoped
// snapshots, and the shared catalog separately, so the dispatcher can encode
// the catalog once and append the encoded bytes to every published snapshot.
// Protobuf wire format merges concatenated messages (repeated fields append),
// so tenant bytes + catalog bytes decode as one full snapshot on the data
// plane; both halves use deterministic marshaling, keeping version hashes
// stable across replicas.
type PartitionedCompiler interface {
	CompileAll(ctx context.Context) (global *readmodel.Snapshot, scoped map[string]*readmodel.Snapshot, catalog *readmodel.Snapshot, err error)
}

// DispatcherConfig tunes the debounce/backstop cadence, the outbox safety bound
// and how long the outbox cursor waits for a missing seq.
type DispatcherConfig struct {
	Debounce  time.Duration
	Backstop  time.Duration
	Retention time.Duration
	MaxRows   int
	GapExpiry time.Duration
}

// Dispatcher compiles the config snapshot, holds it for the gRPC server to serve,
// broadcasts the new version to connected data planes, and reads the
// change-marker outbox through its own cursor. A committed admin write leaves a
// durable marker; every replica observes the markers visible before a compile
// and never deletes them, so one replica's compile cannot hide a change from
// another. Markers leave the outbox only through the retention prune.
type Dispatcher struct {
	compiler    SnapshotCompiler
	codec       configsync.SnapshotCodec[*readmodel.Snapshot]
	holder      *Holder
	broadcaster configsyncport.VersionBroadcaster
	outbox      configsyncport.OutboxRepository
	logger      *slog.Logger
	debounce    time.Duration
	backstop    time.Duration
	retention   time.Duration
	maxRows     int
	trigger     chan struct{}
	compiled    atomic.Bool

	cursor            *outboxCursor
	compileWhileDirty bool

	fragmentEncoder FragmentEncoder
	incremental     *incrementalState

	mu              sync.Mutex
	publishedGlobal string
	publishedScoped map[string]string

	// lkg persists the compiled snapshots; nil when the feature is off.
	lkg *lkgState

	// lastCatalog and lastScoped hold the previous compile's encoded catalog
	// and scoped snapshots, so a scope whose bytes did not change keeps its
	// held slices and version instead of being hashed and held again. Only
	// the dispatch loop reads or writes them.
	lastCatalog []byte
	lastScoped  map[string]ScopedSnapshot
}

// partsVersioner is implemented by codecs that can version a concatenation
// of segments without building it.
type partsVersioner interface {
	VersionParts(parts ...[]byte) string
}

// Readiness reports whether the admin has a snapshot to serve: one compiled in
// this process after startup migrations, or a restored last-good snapshot while
// compiling fails. Gating on a fresh compile alone would take every admin out
// of its Service whenever a restart meets a compile failure, which is exactly
// the outage the persisted snapshot exists to ride out.
func (d *Dispatcher) Readiness(context.Context) error {
	if d.compiled.Load() || d.Source() == SourcePersisted {
		return nil
	}
	return configsync.ErrNotReady
}

// NewDispatcher builds the control-plane snapshot dispatcher.
func NewDispatcher(
	compiler SnapshotCompiler,
	codec configsync.SnapshotCodec[*readmodel.Snapshot],
	holder *Holder,
	broadcaster configsyncport.VersionBroadcaster,
	outbox configsyncport.OutboxRepository,
	logger *slog.Logger,
	cfg DispatcherConfig,
	opts ...DispatcherOption,
) *Dispatcher {
	if logger == nil {
		logger = slog.Default()
	}
	debounce := cfg.Debounce
	if debounce <= 0 {
		debounce = defaultDebounce
	}
	backstop := cfg.Backstop
	if backstop <= 0 {
		backstop = defaultBackstop
	}
	retention := cfg.Retention
	if retention <= 0 {
		retention = defaultRetention
	}
	maxRows := cfg.MaxRows
	if maxRows <= 0 {
		maxRows = defaultMaxRows
	}
	d := &Dispatcher{
		compiler:        compiler,
		codec:           codec,
		holder:          holder,
		broadcaster:     broadcaster,
		outbox:          outbox,
		logger:          logger,
		debounce:        debounce,
		backstop:        backstop,
		retention:       retention,
		maxRows:         maxRows,
		trigger:         make(chan struct{}, 1),
		publishedScoped: make(map[string]string),
		cursor:          newOutboxCursor(cfg.GapExpiry, retention, defaultLateBound),
	}
	for _, opt := range opts {
		opt(d)
	}
	d.enableIncremental()
	return d
}

// WithCompileWhileDirty makes Run dispatch on every Signal with no debounce:
// signals that arrive during a compile fold into one follow-up dispatch that
// starts as soon as the compile ends.
func WithCompileWhileDirty() DispatcherOption {
	return func(d *Dispatcher) {
		d.compileWhileDirty = true
	}
}

// Signal requests a dispatch after an admin write: immediate when the loop is
// quiet, folded into the trailing debounced dispatch during a write burst.
func (d *Dispatcher) Signal() {
	select {
	case d.trigger <- struct{}{}:
	default:
	}
}

// Run drives the dispatch loop until ctx is cancelled, starting with a compile
// so a restarted replica catches up on writes it missed. By default it
// dispatches on the first Signal after a quiet period, so a single admin write
// reaches data planes without sitting out the debounce, and folds the rest of
// a Signal burst into one trailing debounced dispatch. With compile-while-dirty
// it dispatches on every Signal with no timer. Both run a backstop dispatch.
func (d *Dispatcher) Run(ctx context.Context) error {
	d.Signal()
	if d.compileWhileDirty {
		return d.runCompileWhileDirty(ctx)
	}

	timer := time.NewTimer(d.debounce)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	ticker := time.NewTicker(d.backstop)
	defer ticker.Stop()

	var armed bool
	var lastDispatch time.Time
	dispatch := func(failMsg string, reason compileReason) {
		lastDispatch = time.Now()
		if err := d.dispatch(ctx, reason); err != nil && ctx.Err() == nil {
			d.logger.Error(failMsg,
				slog.String("component", component), slog.String("error", err.Error()))
		}
	}
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.trigger:
			if armed {
				continue
			}
			// A dispatch within the last debounce window means this Signal is part
			// of a burst: fold it into one trailing dispatch when the window closes.
			// Otherwise dispatch on the leading edge so the write propagates now.
			if wait := d.debounce - time.Since(lastDispatch); wait > 0 {
				timer.Reset(wait)
				armed = true
				continue
			}
			dispatch("dispatch failed", compileReasonSignal)
		case <-timer.C:
			armed = false
			dispatch("dispatch failed", compileReasonSignal)
		case <-ticker.C:
			dispatch("backstop dispatch failed", compileReasonBackstop)
		}
	}
}

// runCompileWhileDirty dispatches as soon as a Signal arrives. The trigger holds
// one pending Signal, so every Signal received during a compile folds into one
// follow-up dispatch that starts as soon as the current one ends.
func (d *Dispatcher) runCompileWhileDirty(ctx context.Context) error {
	ticker := time.NewTicker(d.backstop)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.trigger:
			if err := d.dispatch(ctx, compileReasonSignal); err != nil && ctx.Err() == nil {
				d.logger.Error("dispatch failed",
					slog.String("component", component), slog.String("error", err.Error()))
			}
		case <-ticker.C:
			if err := d.dispatch(ctx, compileReasonBackstop); err != nil && ctx.Err() == nil {
				d.logger.Error("backstop dispatch failed",
					slog.String("component", component), slog.String("error", err.Error()))
			}
		}
	}
}

// Dispatch runs one dispatch cycle synchronously. It must not run concurrently
// with Run or another Dispatch: the outbox cursor belongs to the dispatch loop.
func (d *Dispatcher) Dispatch(ctx context.Context) error {
	return d.dispatch(ctx, compileReasonSignal)
}

func (d *Dispatcher) dispatch(ctx context.Context, reason compileReason) error {
	// Prune runs on every cycle, including compile-failure returns, so a persistent
	// compile outage can never grow the outbox past its retention/row bound.
	defer func() {
		if _, err := d.outbox.PruneOlderThan(ctx, time.Now().Add(-d.retention), d.maxRows); err != nil && ctx.Err() == nil {
			d.logger.Warn("outbox prune failed",
				slog.String("component", component), slog.String("error", err.Error()))
		}
	}()

	// Observe the markers visible before compiling: their writes are committed,
	// so the compile sees them. A marker that becomes visible mid-cycle is read
	// on the next one, and the cursor advances only once this cycle succeeds.
	next, dirty, observed := d.observeOutbox(ctx)

	reason = d.compileReason(reason, dirty)
	stages := newCompileStages()
	compileStart := time.Now()
	compiledAt := d.compiledAt()
	compiled, mode, reason, err := d.build(ctx, reason, dirty, next, observed, stages)
	if err != nil {
		recordCompile(ctx, d.logger, mode, reason, stages, false)
		d.warnServingPersisted(err)
		return err
	}
	compileDuration := time.Since(compileStart)
	recordCompile(ctx, d.logger, mode, reason, stages, true)
	if compiled.scoped != nil {
		d.lastCatalog, d.lastScoped = compiled.catalog, compiled.scoped
	}
	if d.incremental != nil {
		d.incremental.remember(compiled)
	}
	raw, version, scoped := compiled.raw, compiled.version, compiled.scoped

	// The global snapshot leaves out gateways served by a hybrid data plane, so it
	// is not a safe outer gate on its own: a change to a hosted gateway bumps the
	// global version and that gateway's scoped version, while a change to a hybrid
	// one bumps only its scoped version. Either one publishes, and only the scopes
	// whose version moved are notified.
	d.mu.Lock()
	globalChanged := version != d.publishedGlobal
	published := globalChanged || d.scopesChanged(scoped)
	if published {
		if scoped != nil {
			d.holder.SetPartitioned(raw, version, scoped)
		} else {
			d.holder.Set(raw, version)
		}
		if compiled.layered != nil {
			d.holder.SetLayered(*compiled.layered)
		} else {
			d.holder.ClearLayered()
		}
		if globalChanged {
			d.broadcastScope(compiled.layered, "", version)
			d.publishedGlobal = version
		}
		for scope, snap := range scoped {
			if d.publishedScoped[scope] != snap.Version {
				d.broadcastScope(compiled.layered, scope, snap.Version)
				d.publishedScoped[scope] = snap.Version
			}
		}
		for scope := range d.publishedScoped {
			if _, ok := scoped[scope]; !ok {
				delete(d.publishedScoped, scope)
			}
		}
		d.logger.Info("published config snapshot",
			slog.String("component", component),
			slog.String("version", version),
			slog.Duration("compile", compileDuration),
			slog.String("mode", string(mode)),
			slog.String("reason", string(reason)),
			slog.Int("dirty", len(dirty.gateways)),
			stages.logAttr(),
			slog.Int("bytes", len(raw)),
			slog.Int("scopes", compiled.scopes.count),
			slog.String("largest_scope", compiled.scopes.largest),
			slog.Int("largest_scope_bytes", compiled.scopes.largestBytes))
	}
	d.mu.Unlock()
	if published {
		recordSnapshotPublish(ctx, d.logger, compiled)
	}

	// A snapshot that compiled is the freshest truth: it replaces a restored one
	// as the source, and is persisted. Persisting never fails the dispatch.
	d.markCompiled(compiledAt)
	d.compiled.Store(true)
	d.persist(ctx, raw, version, scoped, compiledAt)

	if observed {
		d.cursor.commit(next)
	}
	return nil
}

func (d *Dispatcher) compileReason(trigger compileReason, dirty dirtySet) compileReason {
	switch {
	case !d.compiled.Load() && d.Source() == SourcePersisted:
		return compileReasonLKGRestore
	case !d.compiled.Load():
		return compileReasonBoot
	case dirty.full:
		return dirty.fullReason
	case trigger == compileReasonSignal && d.incremental == nil:
		return compileReasonSwitchOff
	}
	return trigger
}

// observeOutbox reads the markers above the cursor and the expired gaps that
// became visible since. On a read error it observes nothing, and the next
// cycle reads the same markers again.
func (d *Dispatcher) observeOutbox(ctx context.Context) (cursorState, dirtySet, bool) {
	markers, minSeq, err := d.outbox.ReadSince(ctx, d.cursor.readFrom())
	if err == nil {
		var lateFound []configsyncport.Marker
		lateFound, err = d.outbox.ReadSeqs(ctx, d.cursor.lateSeqs())
		if err == nil {
			next, dirty := d.cursor.observe(markers, lateFound, minSeq, time.Now())
			return next, dirty, true
		}
	}
	if ctx.Err() == nil {
		d.logger.Warn("outbox read failed; the markers are read again next cycle",
			slog.String("component", component), slog.String("error", err.Error()))
	}
	return cursorState{}, dirtySet{}, false
}

type compiledSnapshot struct {
	raw          []byte
	version      string
	scoped       map[string]ScopedSnapshot
	catalog      []byte
	catalogBytes int
	// globalTenant is the global snapshot without the catalog, set by the
	// incremental path so an unchanged one can be recognised next cycle.
	globalTenant []byte
	// layered is set only by the fragment encoder; without it data planes
	// that pull layered snapshots fall back to the single blob.
	layered  *Layered
	scopes   scopeSizes
	entities snapshotEntities
}

func (d *Dispatcher) scopesChanged(scoped map[string]ScopedSnapshot) bool {
	for scope, snap := range scoped {
		if d.publishedScoped[scope] != snap.Version {
			return true
		}
	}
	for scope := range d.publishedScoped {
		if _, ok := scoped[scope]; !ok {
			return true
		}
	}
	return false
}

func (d *Dispatcher) compile(ctx context.Context, stages *compileStages) (compiledSnapshot, error) {
	if partitioned, ok := d.compiler.(PartitionedCompiler); ok {
		global, scopedSnaps, catalog, cerr := d.compileAll(ctx, partitioned, stages)
		if cerr != nil {
			return compiledSnapshot{}, fmt.Errorf("configsnapshot: compile: %w", cerr)
		}
		// The catalog is usually the bulk of the encoded bytes and identical in
		// every snapshot, so encode it once and share the bytes across scopes.
		encodeStart := time.Now()
		catalogRaw, eerr := d.codec.Encode(catalog)
		stages.since(stageEncode, encodeStart)
		if eerr != nil {
			return compiledSnapshot{}, fmt.Errorf("configsnapshot: encode catalog: %w", eerr)
		}
		catalogUnchanged := d.lastCatalog != nil && bytes.Equal(d.lastCatalog, catalogRaw)
		if catalogUnchanged {
			catalogRaw = d.lastCatalog
		}
		raw, version, err := d.encodeWithCatalog(global, catalogRaw, stages)
		if err != nil {
			return compiledSnapshot{}, err
		}
		compiled := compiledSnapshot{raw: raw, version: version, scoped: make(map[string]ScopedSnapshot, len(scopedSnaps)), catalog: catalogRaw, catalogBytes: len(catalogRaw)}
		for scope, snap := range scopedSnaps {
			encodeStart = time.Now()
			tenantRaw, serr := d.codec.Encode(snap)
			stages.since(stageEncode, encodeStart)
			if serr != nil {
				return compiledSnapshot{}, fmt.Errorf("configsnapshot: encode: %w", serr)
			}
			scoped := ScopedSnapshot{Raw: tenantRaw, Catalog: catalogRaw}
			if prev, ok := d.lastScoped[scope]; ok && catalogUnchanged && prev.Catalog != nil && bytes.Equal(prev.Raw, tenantRaw) {
				scoped = prev
			} else {
				hashStart := time.Now()
				scoped.Version = d.versionParts(tenantRaw, catalogRaw)
				stages.since(stageHash, hashStart)
			}
			compiled.scoped[scope] = scoped
			compiled.scopes.add(scope, scoped.Len())
			compiled.entities.add(snap)
		}
		return compiled, nil
	}

	readStart := time.Now()
	snapshot, cerr := d.compiler.Compile(ctx)
	stages.since(stageRead, readStart)
	if cerr != nil {
		return compiledSnapshot{}, fmt.Errorf("configsnapshot: compile: %w", cerr)
	}
	raw, version, err := d.encode(snapshot, stages)
	if err != nil {
		return compiledSnapshot{}, err
	}
	compiled := compiledSnapshot{raw: raw, version: version}
	compiled.entities.add(snapshot)
	return compiled, nil
}

// encodeWithCatalog encodes a tenant-only snapshot and appends the
// pre-encoded catalog bytes. Protobuf unmarshal merges the concatenation into
// one full snapshot; the version hashes the exact bytes served.
func (d *Dispatcher) encodeWithCatalog(snapshot *readmodel.Snapshot, catalogRaw []byte, stages *compileStages) ([]byte, string, error) {
	encodeStart := time.Now()
	tenantRaw, err := d.codec.Encode(snapshot)
	stages.since(stageEncode, encodeStart)
	if err != nil {
		return nil, "", fmt.Errorf("configsnapshot: encode: %w", err)
	}
	mergeStart := time.Now()
	raw := make([]byte, 0, len(tenantRaw)+len(catalogRaw))
	raw = append(raw, tenantRaw...)
	raw = append(raw, catalogRaw...)
	stages.since(stageMerge, mergeStart)
	hashStart := time.Now()
	version := d.codec.Version(raw)
	stages.since(stageHash, hashStart)
	return raw, version, nil
}

func (d *Dispatcher) compileAll(ctx context.Context, compiler PartitionedCompiler, stages *compileStages) (*readmodel.Snapshot, map[string]*readmodel.Snapshot, *readmodel.Snapshot, error) {
	if staged, ok := compiler.(stagedCompiler); ok {
		return staged.compileAllStaged(ctx, stages)
	}
	readStart := time.Now()
	defer stages.since(stageRead, readStart)
	return compiler.CompileAll(ctx)
}

func (d *Dispatcher) versionParts(parts ...[]byte) string {
	if v, ok := d.codec.(partsVersioner); ok {
		return v.VersionParts(parts...)
	}
	return d.codec.Version(bytes.Join(parts, nil))
}

func (d *Dispatcher) encode(snapshot *readmodel.Snapshot, stages *compileStages) ([]byte, string, error) {
	encodeStart := time.Now()
	raw, err := d.codec.Encode(snapshot)
	stages.since(stageEncode, encodeStart)
	if err != nil {
		return nil, "", fmt.Errorf("configsnapshot: encode: %w", err)
	}
	hashStart := time.Now()
	version := d.codec.Version(raw)
	stages.since(stageHash, hashStart)
	return raw, version, nil
}

// layeredBroadcaster is implemented by broadcasters that tell each data plane
// the version matching how it pulls: the manifest version to one that pulls
// layered snapshots, the single-blob version to any other.
type layeredBroadcaster interface {
	BroadcastScopeLayered(scope, version, layeredVersion string)
}

func (d *Dispatcher) broadcastScope(layered *Layered, scope, version string) {
	lb, ok := d.broadcaster.(layeredBroadcaster)
	if !ok || layered == nil {
		d.broadcaster.BroadcastScope(scope, version)
		return
	}
	manifest := layered.Global
	if scope != "" {
		manifest = layered.Scoped[scope]
	}
	lb.BroadcastScopeLayered(scope, version, manifest.Version)
}
