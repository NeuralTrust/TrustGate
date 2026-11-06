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
	"log/slog"
	"sort"
	"time"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const (
	driftMetric    = "trustgate.configsnapshot.drift"
	scopeKindAttr  = "scope_kind"
	maxDriftLogged = 10
)

// WithIncrementalCompile makes the dispatcher recompile only what the outbox
// markers name, through encoder, and compile as soon as a change arrives with
// no debounce. It needs a compiler that is also an IncrementalSource; with any
// other compiler the option is ignored and every compile stays full.
func WithIncrementalCompile(encoder FragmentEncoder) DispatcherOption {
	return func(d *Dispatcher) {
		d.fragmentEncoder = encoder
	}
}

// incrementalState is what the dispatch loop keeps between incremental
// compiles. Only the dispatch loop reads or writes it.
type incrementalState struct {
	encoder FragmentEncoder
	source  IncrementalSource
	// ready is false until a full compile has filled the encoder, so the first
	// cycle after a start or a restored snapshot is always a full one.
	ready    bool
	entities map[ids.GatewayID]snapshotEntities

	lastGlobalTenant  []byte
	lastGlobalRaw     []byte
	lastGlobalVersion string
}

func (s *incrementalState) remember(compiled compiledSnapshot) {
	s.lastGlobalTenant, s.lastGlobalRaw, s.lastGlobalVersion = compiled.globalTenant, compiled.raw, compiled.version
}

func (s *incrementalState) entityTotals() snapshotEntities {
	var total snapshotEntities
	for _, n := range s.entities {
		total.auths += n.auths
		total.ownedAuths += n.ownedAuths
		total.personalConsumers += n.personalConsumers
		total.personalLinks += n.personalLinks
	}
	return total
}

func (d *Dispatcher) enableIncremental() {
	if d.fragmentEncoder == nil {
		return
	}
	source, ok := d.compiler.(IncrementalSource)
	if !ok {
		d.logger.Warn("incremental compile needs a compiler that reads gateways on their own; every compile stays full",
			slog.String("component", component))
		return
	}
	d.incremental = &incrementalState{
		encoder:  d.fragmentEncoder,
		source:   source,
		entities: make(map[ids.GatewayID]snapshotEntities),
	}
	d.compileWhileDirty = true
}

// build produces the snapshot of one cycle. Without incremental compile it is
// always the full compile. With it, a cycle triggered by a write recompiles
// only the dirty gateways; boot, a restored snapshot, a marker that names
// nothing, a cursor reset and an outbox that could not be read rebuild
// everything, and so does an incremental cycle that fails for any reason. The
// backstop rebuilds everything too, after comparing that rebuild against the
// incremental state.
func (d *Dispatcher) build(ctx context.Context, reason compileReason, dirty dirtySet, next cursorState, observed bool, stages *compileStages) (compiledSnapshot, compileMode, compileReason, error) {
	inc := d.incremental
	if inc == nil {
		compiled, err := d.compile(ctx, stages)
		return compiled, compileModeFull, reason, err
	}
	full := reason != compileReasonSignal
	if !full && (!inc.ready || !observed) {
		full, reason = true, compileReasonCacheMiss
	}
	if !full {
		compiled, err := d.compileIncremental(ctx, dirty, stages)
		if err == nil {
			return compiled, compileModeIncremental, reason, nil
		}
		if ctx.Err() != nil {
			return compiledSnapshot{}, compileModeIncremental, reason, err
		}
		d.logger.Warn("incremental compile failed; compiling everything instead",
			slog.String("component", component), slog.String("error", err.Error()))
		reason = compileReasonCacheMiss
	}
	if reason == compileReasonBackstop && inc.ready && observed {
		compiled, err := d.compileWithDriftCheck(ctx, dirty, next, stages)
		return compiled, compileModeFull, reason, err
	}
	compiled, err := d.compileFullEncoded(ctx, stages)
	return compiled, compileModeFull, reason, err
}

type collectedGateway struct {
	id      ids.GatewayID
	gateway *gatewaydomain.Gateway
	data    *readmodel.Data
}

// compileIncremental reads the dirty gateways, the catalog when it is dirty
// and the shared inputs, re-encodes what was read and assembles the snapshot.
// Global membership comes from each gateway as just read, never from what the
// encoder held, so a gateway that moved to or from a data plane of its own
// lands in the right flavors.
func (d *Dispatcher) compileIncremental(ctx context.Context, dirty dirtySet, stages *compileStages) (compiledSnapshot, error) {
	inc := d.incremental
	readStart := time.Now()
	reads := make([]collectedGateway, 0, len(dirty.gateways))
	for id := range dirty.gateways {
		gateway, data, err := inc.source.CollectGateway(ctx, id)
		if err != nil {
			stages.since(stageRead, readStart)
			return compiledSnapshot{}, err
		}
		reads = append(reads, collectedGateway{id: id, gateway: gateway, data: data})
	}
	var catalog *readmodel.Data
	if dirty.catalog {
		read, err := inc.source.CollectCatalog(ctx)
		if err != nil {
			stages.since(stageRead, readStart)
			return compiledSnapshot{}, err
		}
		catalog = &read
	}
	shared, err := inc.source.ListShared(ctx)
	stages.since(stageRead, readStart)
	if err != nil {
		return compiledSnapshot{}, err
	}

	encodeStart := time.Now()
	for _, read := range reads {
		if read.gateway == nil {
			inc.encoder.Delete(read.id)
			delete(inc.entities, read.id)
			continue
		}
		if err := inc.encoder.Put(*read.gateway, *read.data); err != nil {
			stages.since(stageEncode, encodeStart)
			return compiledSnapshot{}, err
		}
		inc.entities[read.id] = entitiesOf(*read.data)
	}
	if catalog != nil {
		if err := inc.encoder.PutCatalog(*catalog); err != nil {
			stages.since(stageEncode, encodeStart)
			return compiledSnapshot{}, err
		}
	}
	stages.since(stageEncode, encodeStart)
	return d.assembleEncoded(shared, stages)
}

func (d *Dispatcher) compileFullEncoded(ctx context.Context, stages *compileStages) (compiledSnapshot, error) {
	inc := d.incremental
	readStart := time.Now()
	gateways, data, catalog, err := inc.source.CollectAll(ctx)
	if err != nil {
		stages.since(stageRead, readStart)
		return compiledSnapshot{}, err
	}
	shared, err := inc.source.ListShared(ctx)
	stages.since(stageRead, readStart)
	if err != nil {
		return compiledSnapshot{}, err
	}

	encodeStart := time.Now()
	err = inc.encoder.Rebuild(gateways, data, catalog)
	stages.since(stageEncode, encodeStart)
	if err != nil {
		return compiledSnapshot{}, err
	}
	entities := make(map[ids.GatewayID]snapshotEntities, len(data))
	for id, gwData := range data {
		entities[id] = entitiesOf(*gwData)
	}
	inc.entities = entities
	compiled, err := d.assembleEncoded(shared, stages)
	if err != nil {
		return compiledSnapshot{}, err
	}
	inc.ready = true
	return compiled, nil
}

func (d *Dispatcher) assembleEncoded(shared SharedInputs, stages *compileStages) (compiledSnapshot, error) {
	inc := d.incremental
	mergeStart := time.Now()
	assembled, err := inc.encoder.Assemble(shared)
	if err != nil {
		stages.since(stageMerge, mergeStart)
		return compiledSnapshot{}, err
	}
	catalogRaw := assembled.Catalog
	catalogUnchanged := d.lastCatalog != nil && bytes.Equal(d.lastCatalog, catalogRaw)
	if catalogUnchanged {
		catalogRaw = d.lastCatalog
	}

	compiled := compiledSnapshot{
		scoped:       make(map[string]ScopedSnapshot, len(assembled.Scoped)),
		catalog:      catalogRaw,
		catalogBytes: len(catalogRaw),
		globalTenant: assembled.Global,
		entities:     inc.entityTotals(),
		layered:      &assembled.Layered,
	}
	if catalogUnchanged && inc.lastGlobalTenant != nil && bytes.Equal(inc.lastGlobalTenant, assembled.Global) {
		compiled.raw, compiled.version = inc.lastGlobalRaw, inc.lastGlobalVersion
		stages.since(stageMerge, mergeStart)
	} else {
		raw := make([]byte, 0, len(assembled.Global)+len(catalogRaw))
		raw = append(raw, assembled.Global...)
		raw = append(raw, catalogRaw...)
		stages.since(stageMerge, mergeStart)
		hashStart := time.Now()
		compiled.raw, compiled.version = raw, d.codec.Version(raw)
		stages.since(stageHash, hashStart)
	}

	for scope, tenantRaw := range assembled.Scoped {
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
	}
	return compiled, nil
}

// compileWithDriftCheck applies this cycle's markers incrementally, then
// rebuilds everything and publishes the rebuild. The two are compared only
// when no marker this cycle did not see was committed in between: a write that
// landed during the comparison would show up as drift that is not.
func (d *Dispatcher) compileWithDriftCheck(ctx context.Context, dirty dirtySet, next cursorState, stages *compileStages) (compiledSnapshot, error) {
	incremental, ierr := d.compileIncremental(ctx, dirty, nil)
	full, err := d.compileFullEncoded(ctx, stages)
	if err != nil {
		return compiledSnapshot{}, err
	}
	if ierr != nil {
		d.logger.Warn("incremental compile failed on the backstop; publishing the full compile",
			slog.String("component", component), slog.String("error", ierr.Error()))
		return full, nil
	}
	if d.outboxSettled(ctx, next) {
		d.recordDrift(ctx, incremental, full)
	}
	return full, nil
}

func (d *Dispatcher) outboxSettled(ctx context.Context, next cursorState) bool {
	markers, _, err := d.outbox.ReadSince(ctx, next.lowWater)
	if err != nil {
		return false
	}
	for _, m := range markers {
		if _, seen := next.seen[m.Seq]; !seen {
			return false
		}
	}
	return true
}

func (d *Dispatcher) recordDrift(ctx context.Context, incremental, full compiledSnapshot) {
	globalDrift := incremental.version != full.version
	var scopes []string
	for scope, snap := range full.scoped {
		if incremental.scoped[scope].Version != snap.Version {
			scopes = append(scopes, scope)
		}
	}
	for scope := range incremental.scoped {
		if _, ok := full.scoped[scope]; !ok {
			scopes = append(scopes, scope)
		}
	}
	if !globalDrift && len(scopes) == 0 {
		return
	}
	sort.Strings(scopes)
	counter, err := otel.Meter(snapshotMeterName).Int64Counter(driftMetric, metric.WithUnit("{snapshot}"),
		metric.WithDescription("snapshot flavors whose incremental compile differed from the full compile on the backstop"))
	if err != nil {
		warnInstrument(d.logger, driftMetric, err)
	} else {
		if globalDrift {
			counter.Add(ctx, 1, metric.WithAttributes(attribute.String(scopeKindAttr, "global")))
		}
		if len(scopes) > 0 {
			counter.Add(ctx, int64(len(scopes)), metric.WithAttributes(attribute.String(scopeKindAttr, "scoped")))
		}
	}
	logged := scopes
	if len(logged) > maxDriftLogged {
		logged = logged[:maxDriftLogged]
	}
	d.logger.Warn("incremental config snapshot drifted from the full compile; publishing the full compile",
		slog.String("component", component),
		slog.Bool("global", globalDrift),
		slog.Int("scopes", len(scopes)),
		slog.Any("scope_ids", logged))
}

func entitiesOf(data readmodel.Data) snapshotEntities {
	var n snapshotEntities
	n.addData(data)
	return n
}
