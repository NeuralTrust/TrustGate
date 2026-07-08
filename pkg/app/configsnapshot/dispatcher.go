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
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

const component = "configsnapshot"

const (
	defaultDebounce  = 2 * time.Second
	defaultBackstop  = 5 * time.Minute
	defaultRetention = 24 * time.Hour
	defaultMaxRows   = 10000
)

// SnapshotCompiler compiles the current State-of-the-World from the live config.
type SnapshotCompiler interface {
	Compile(ctx context.Context) (*readmodel.Snapshot, error)
}

// PartitionedCompiler additionally compiles one snapshot per partition scope in a
// single pass. A compiler that implements it makes the dispatcher publish
// per-scope snapshots alongside the whole snapshot.
type PartitionedCompiler interface {
	CompileAll(ctx context.Context) (*readmodel.Snapshot, map[string]*readmodel.Snapshot, error)
}

// DispatcherConfig tunes the debounce/backstop cadence and the outbox safety bound.
type DispatcherConfig struct {
	Debounce  time.Duration
	Backstop  time.Duration
	Retention time.Duration
	MaxRows   int
}

// Dispatcher compiles the config snapshot, holds it for the gRPC server to serve,
// broadcasts the new version to connected data planes, and drains the
// change-marker outbox that survives a control-plane restart. A committed admin
// write leaves a durable marker; the dispatcher folds every marker visible before
// the compile into one recompile and drains exactly that observed set.
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

	mu        sync.Mutex
	published string
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
	return &Dispatcher{
		compiler:    compiler,
		codec:       codec,
		holder:      holder,
		broadcaster: broadcaster,
		outbox:      outbox,
		logger:      logger,
		debounce:    debounce,
		backstop:    backstop,
		retention:   retention,
		maxRows:     maxRows,
		trigger:     make(chan struct{}, 1),
	}
}

// Signal requests a debounced dispatch after an admin write.
func (d *Dispatcher) Signal() {
	select {
	case d.trigger <- struct{}{}:
	default:
	}
}

// Run drives the dispatch loop until ctx is cancelled: a debounced dispatch after
// a Signal burst, a jittered backstop dispatch, and an initial catch-up when the
// outbox holds markers left by a write that committed before a prior restart.
func (d *Dispatcher) Run(ctx context.Context) error {
	if pending, err := d.outbox.PendingCount(ctx); err != nil {
		if ctx.Err() == nil {
			d.logger.Warn("outbox pending count failed at boot",
				slog.String("component", component), slog.String("error", err.Error()))
		}
	} else if pending > 0 {
		d.Signal()
	}

	timer := time.NewTimer(d.debounce)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	ticker := time.NewTicker(d.backstop)
	defer ticker.Stop()

	var armed bool
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-d.trigger:
			if !armed {
				timer.Reset(d.debounce)
				armed = true
			}
		case <-timer.C:
			armed = false
			if err := d.dispatch(ctx); err != nil && ctx.Err() == nil {
				d.logger.Error("dispatch failed",
					slog.String("component", component), slog.String("error", err.Error()))
			}
		case <-ticker.C:
			if err := d.dispatch(ctx); err != nil && ctx.Err() == nil {
				d.logger.Error("backstop dispatch failed",
					slog.String("component", component), slog.String("error", err.Error()))
			}
		}
	}
}

// Dispatch runs one dispatch cycle synchronously. It must not run concurrently
// with Run or another Dispatch: the outbox frontier (MaxSeq/DeleteUpTo) is not
// mutually exclusive across cycles, so overlapping callers could drain against
// different frontiers.
func (d *Dispatcher) Dispatch(ctx context.Context) error {
	return d.dispatch(ctx)
}

func (d *Dispatcher) dispatch(ctx context.Context) error {
	// Prune runs on every cycle, including compile-failure returns, so a persistent
	// compile outage can never grow the outbox past its retention/row bound.
	defer func() {
		if _, err := d.outbox.PruneOlderThan(ctx, time.Now().Add(-d.retention), d.maxRows); err != nil && ctx.Err() == nil {
			d.logger.Warn("outbox prune failed",
				slog.String("component", component), slog.String("error", err.Error()))
		}
	}()

	// Capture the set of markers visible before compiling. Draining exactly this set
	// (rather than a seq range) guarantees a marker that becomes visible mid-cycle —
	// including a lower seq that commits after a higher one, since seq is assigned at
	// INSERT not COMMIT — survives to trigger the next dispatch.
	pending, err := d.outbox.Pending(ctx)
	if err != nil {
		if ctx.Err() == nil {
			d.logger.Warn("outbox pending read failed; skipping drain this cycle",
				slog.String("component", component), slog.String("error", err.Error()))
		}
		pending = nil
	}

	raw, version, scoped, err := d.compile(ctx)
	if err != nil {
		return err
	}

	d.mu.Lock()
	if version != d.published {
		if scoped != nil {
			d.holder.SetPartitioned(raw, version, scoped)
		} else {
			d.holder.Set(raw, version)
		}
		d.broadcaster.Broadcast(version)
		d.published = version
	}
	d.mu.Unlock()

	if len(pending) > 0 {
		if _, err := d.outbox.DeleteSeqs(ctx, pending); err != nil && ctx.Err() == nil {
			d.logger.Warn("outbox drain failed",
				slog.String("component", component), slog.String("error", err.Error()))
		}
	}
	return nil
}

// compile encodes the whole snapshot and, when the compiler is partitioned, the
// per-scope snapshots. A nil scoped map means the whole-snapshot-only path.
func (d *Dispatcher) compile(ctx context.Context) (raw []byte, version string, scoped map[string]ScopedSnapshot, err error) {
	if partitioned, ok := d.compiler.(PartitionedCompiler); ok {
		global, scopedSnaps, cerr := partitioned.CompileAll(ctx)
		if cerr != nil {
			return nil, "", nil, fmt.Errorf("configsnapshot: compile: %w", cerr)
		}
		raw, version, err = d.encode(global)
		if err != nil {
			return nil, "", nil, err
		}
		scoped = make(map[string]ScopedSnapshot, len(scopedSnaps))
		for scope, snap := range scopedSnaps {
			scopedRaw, scopedVersion, eerr := d.encode(snap)
			if eerr != nil {
				return nil, "", nil, eerr
			}
			scoped[scope] = ScopedSnapshot{Raw: scopedRaw, Version: scopedVersion}
		}
		return raw, version, scoped, nil
	}

	snapshot, cerr := d.compiler.Compile(ctx)
	if cerr != nil {
		return nil, "", nil, fmt.Errorf("configsnapshot: compile: %w", cerr)
	}
	raw, version, err = d.encode(snapshot)
	if err != nil {
		return nil, "", nil, err
	}
	return raw, version, nil, nil
}

func (d *Dispatcher) encode(snapshot *readmodel.Snapshot) ([]byte, string, error) {
	raw, err := d.codec.Encode(snapshot)
	if err != nil {
		return nil, "", fmt.Errorf("configsnapshot: encode: %w", err)
	}
	return raw, d.codec.Version(raw), nil
}
