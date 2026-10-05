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
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync/atomic"
	"time"
)

const (
	// DefaultLKGMaxAge bounds how stale a persisted snapshot may be and still be
	// served after a restart.
	DefaultLKGMaxAge = 7 * 24 * time.Hour
	// lkgOpTimeout bounds a persist cycle and a restore so neither can stall the
	// dispatch loop or the boot.
	lkgOpTimeout = 30 * time.Second
	// lkgTouchInterval is how often an unchanged snapshot's persisted age is
	// refreshed. It is far below any sensible max age.
	lkgTouchInterval = time.Hour
)

// SnapshotSource says where the admin's served snapshot came from.
type SnapshotSource int32

const (
	// SourceNone means the admin serves nothing yet.
	SourceNone SnapshotSource = iota
	// SourceCompiled means the served snapshot came from a successful compile.
	SourceCompiled
	// SourcePersisted means the served snapshot was restored from the LKG store
	// and no compile has succeeded since.
	SourcePersisted
)

func (s SnapshotSource) String() string {
	switch s {
	case SourceCompiled:
		return "compiled"
	case SourcePersisted:
		return "persisted"
	default:
		return "none"
	}
}

// LKGConfig tunes the admin's persisted last-good snapshot.
type LKGConfig struct {
	// MaxAge refuses a persisted row older than this. Zero means DefaultLKGMaxAge.
	MaxAge time.Duration
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// DispatcherOption customises a Dispatcher.
type DispatcherOption func(*Dispatcher)

// WithLKG makes the dispatcher persist every successfully compiled snapshot and
// lets Restore serve the persisted one after a restart. Without it the
// dispatcher behaves exactly as before.
func WithLKG(store LKGStore, sealer LKGSealer, cfg LKGConfig) DispatcherOption {
	return func(d *Dispatcher) {
		if store == nil || sealer == nil {
			return
		}
		l := &lkgState{store: store, sealer: sealer, maxAge: cfg.MaxAge, now: cfg.Now, persisted: map[string]string{}}
		if l.maxAge <= 0 {
			l.maxAge = DefaultLKGMaxAge
		}
		if l.now == nil {
			l.now = time.Now
		}
		d.lkg = l
	}
}

type lkgState struct {
	store  LKGStore
	sealer LKGSealer
	maxAge time.Duration
	now    func() time.Time

	// persisted maps a scope to the version known to be stored for it. Only the
	// dispatch loop touches it, and dispatch is serial by contract.
	persisted map[string]string
	lastTouch time.Time

	source   atomic.Int32
	servedAt atomic.Int64 // unix nanos when the served snapshot was compiled
}

// Source reports where the served snapshot came from.
func (d *Dispatcher) Source() SnapshotSource {
	if d.lkg == nil {
		return SourceNone
	}
	return SnapshotSource(d.lkg.source.Load())
}

// SnapshotAge is the age of the served snapshot: since its compile, or, for a
// persisted one, since the compile that produced it. ok is false when nothing
// is served.
func (d *Dispatcher) SnapshotAge() (time.Duration, bool) {
	if d.lkg == nil || d.Source() == SourceNone {
		return 0, false
	}
	return d.lkg.now().Sub(time.Unix(0, d.lkg.servedAt.Load())), true
}

// Restore loads the persisted snapshots into the holder so the admin serves
// them until a compile succeeds. It never blocks past a bound and never fails:
// a row it cannot trust is skipped with a WARN, and a store error leaves the
// holder empty exactly as before. Call it once, before Run.
func (d *Dispatcher) Restore(ctx context.Context) {
	l := d.lkg
	if l == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, lkgOpTimeout)
	defer cancel()

	records, err := l.store.Load(ctx)
	if err != nil {
		recordLKGLoad(ctx, "error")
		d.logger.Warn("persisted config snapshot could not be loaded",
			slog.String("component", component), slog.String("error", err.Error()))
		return
	}

	type restored struct {
		raw        []byte
		version    string
		compiledAt time.Time
	}
	good := map[string]restored{}
	for _, rec := range records {
		raw, reason := d.openRecord(rec)
		if reason != "" {
			recordLKGLoad(ctx, reason)
			d.logger.Warn("persisted config snapshot row rejected",
				slog.String("component", component),
				slog.String("scope", rec.Scope), slog.String("reason", reason))
			continue
		}
		good[rec.Scope] = restored{raw: raw, version: rec.Version, compiledAt: rec.CompiledAt}
	}

	global, ok := good[GlobalScope]
	if !ok {
		if len(records) > 0 {
			d.logger.Warn("no usable persisted global config snapshot; serving nothing until a compile succeeds",
				slog.String("component", component))
		}
		return
	}
	scoped := make(map[string]ScopedSnapshot, len(good))
	oldest := global.compiledAt
	for scope, r := range good {
		l.persisted[scope] = r.version
		if scope == GlobalScope {
			continue
		}
		scoped[scope] = ScopedSnapshot{Raw: r.raw, Version: r.version}
		if r.compiledAt.Before(oldest) {
			oldest = r.compiledAt
		}
	}
	d.holder.SetPartitioned(global.raw, global.version, scoped)
	l.servedAt.Store(oldest.UnixNano())
	l.source.Store(int32(SourcePersisted))
	for range good {
		recordLKGLoad(ctx, "ok")
	}
	d.logger.Warn("serving persisted config snapshot until a compile succeeds",
		slog.String("component", component),
		slog.String("version", global.version),
		slog.Int("scopes", len(scoped)),
		slog.Duration("age", l.now().Sub(oldest)))
}

// openRecord returns the snapshot bytes of a trustworthy row, or the reason the
// row is not trusted.
func (d *Dispatcher) openRecord(rec LKGRecord) ([]byte, string) {
	l := d.lkg
	if rec.KeyID != l.sealer.KeyID() {
		return nil, "key_mismatch"
	}
	if l.now().Sub(rec.CompiledAt) > l.maxAge {
		return nil, "expired"
	}
	raw, err := l.sealer.Open(rec.Scope, rec.Version, rec.Payload)
	if err != nil {
		return nil, "undecryptable"
	}
	if d.codec.Version(raw) != rec.Version {
		return nil, "checksum_mismatch"
	}
	return raw, ""
}

// compiledAt stamps a compile with the persistence clock.
func (d *Dispatcher) compiledAt() time.Time {
	if d.lkg != nil {
		return d.lkg.now()
	}
	return time.Now()
}

// markCompiled records that the served snapshot now comes from a compile that
// began at compiledAt.
func (d *Dispatcher) markCompiled(compiledAt time.Time) {
	if d.lkg == nil {
		return
	}
	d.lkg.servedAt.Store(compiledAt.UnixNano())
	d.lkg.source.Store(int32(SourceCompiled))
}

// warnServingPersisted is the signal operators watch: every failed dispatch
// while the admin is serving a restored snapshot says so.
func (d *Dispatcher) warnServingPersisted(err error) {
	if d.Source() != SourcePersisted {
		return
	}
	age, _ := d.SnapshotAge()
	d.logger.Warn("compile failed; still serving the persisted config snapshot",
		slog.String("component", component),
		slog.Duration("age", age), slog.String("error", err.Error()))
}

// persist stores the scopes of a successful compile whose version is not already
// stored, deletes the scopes that vanished, and refreshes the age of the rest. A
// failure is logged and counted and never fails the dispatch; the next cycle
// retries what did not land.
func (d *Dispatcher) persist(ctx context.Context, raw []byte, version string, scoped map[string]ScopedSnapshot, compiledAt time.Time) {
	l := d.lkg
	if l == nil {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, lkgOpTimeout)
	defer cancel()

	current := make(map[string]ScopedSnapshot, len(scoped)+1)
	current[GlobalScope] = ScopedSnapshot{Raw: raw, Version: version}
	for scope, snap := range scoped {
		current[scope] = snap
	}
	scopes := make([]string, 0, len(current))
	for scope := range current {
		scopes = append(scopes, scope)
	}
	sort.Strings(scopes)

	if l.lastTouch.IsZero() {
		// The rows written this cycle are fresh; the first refresh is due one
		// interval from now.
		l.lastTouch = compiledAt
	}
	var unchanged []LKGVersion
	failed := false
	for _, scope := range scopes {
		snap := current[scope]
		if l.persisted[scope] == snap.Version {
			unchanged = append(unchanged, LKGVersion{Scope: scope, Version: snap.Version})
			continue
		}
		if err := d.persistScope(ctx, scope, snap, compiledAt); err != nil {
			failed = true
			recordLKGPersist(ctx, "error")
			d.logger.Warn("persisting config snapshot failed",
				slog.String("component", component),
				slog.String("scope", scope), slog.String("error", err.Error()))
		}
	}

	if !failed {
		if err := l.store.DeleteVanished(ctx, scopes, compiledAt); err != nil {
			d.logger.Warn("deleting vanished persisted snapshots failed",
				slog.String("component", component), slog.String("error", err.Error()))
		}
		for scope := range l.persisted {
			if _, ok := current[scope]; !ok {
				delete(l.persisted, scope)
			}
		}
	}

	if len(unchanged) > 0 && compiledAt.Sub(l.lastTouch) >= lkgTouchInterval {
		if err := l.store.Touch(ctx, unchanged, compiledAt); err != nil {
			d.logger.Warn("refreshing persisted snapshot age failed",
				slog.String("component", component), slog.String("error", err.Error()))
		} else {
			l.lastTouch = compiledAt
		}
	}
}

func (d *Dispatcher) persistScope(ctx context.Context, scope string, snap ScopedSnapshot, compiledAt time.Time) error {
	l := d.lkg
	payload, err := l.sealer.Seal(scope, snap.Version, snap.Raw)
	if err != nil {
		return fmt.Errorf("seal: %w", err)
	}
	written, err := l.store.Save(ctx, LKGRecord{
		Scope: scope, Version: snap.Version, CompiledAt: compiledAt,
		KeyID: l.sealer.KeyID(), Payload: payload,
	})
	if err != nil {
		return err
	}
	if written {
		recordLKGPersist(ctx, "ok")
	} else {
		// A newer compile from another replica holds the row. Treat the scope as
		// stored so this replica does not re-seal and resend it every cycle.
		recordLKGPersist(ctx, "superseded")
	}
	l.persisted[scope] = snap.Version
	return nil
}
