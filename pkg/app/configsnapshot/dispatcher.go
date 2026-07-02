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
// write leaves a durable marker; the dispatcher folds every marker at or below the
// pre-compile frontier into one recompile and drains them in a single delete.
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

// Dispatch runs one dispatch cycle synchronously.
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

	// Snapshot the marker frontier before compiling so a write that lands mid-cycle
	// keeps a marker above the frontier and triggers the next dispatch.
	maxSeq, err := d.outbox.MaxSeq(ctx)
	if err != nil {
		if ctx.Err() == nil {
			d.logger.Warn("outbox max seq failed; skipping drain this cycle",
				slog.String("component", component), slog.String("error", err.Error()))
		}
		maxSeq = 0
	}

	snapshot, err := d.compiler.Compile(ctx)
	if err != nil {
		return fmt.Errorf("configsnapshot: compile: %w", err)
	}
	raw, err := d.codec.Encode(snapshot)
	if err != nil {
		return fmt.Errorf("configsnapshot: encode: %w", err)
	}
	version := d.codec.Version(raw)

	d.mu.Lock()
	if version != d.published {
		d.holder.Set(raw, version)
		d.broadcaster.Broadcast(version)
		d.published = version
	}
	d.mu.Unlock()

	if maxSeq > 0 {
		if _, err := d.outbox.DeleteUpTo(ctx, maxSeq); err != nil && ctx.Err() == nil {
			d.logger.Warn("outbox drain failed",
				slog.String("component", component), slog.String("error", err.Error()))
		}
	}
	return nil
}
