package configsnapshot

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
)

const component = "configsnapshot"

const (
	defaultDebounce = 2 * time.Second
	defaultBackstop = 5 * time.Minute
)

type snapshotCompiler interface {
	Compile(ctx context.Context) (*readmodel.Snapshot, error)
}

type RecompilerConfig struct {
	Debounce time.Duration
	Backstop time.Duration
}

type Recompiler struct {
	compiler snapshotCompiler
	codec    configsync.SnapshotCodec[*readmodel.Snapshot]
	holder   *Holder
	notifier configsync.ChangeNotifier
	logger   *slog.Logger
	debounce time.Duration
	backstop time.Duration
	trigger  chan struct{}

	mu        sync.Mutex
	published string
}

func NewRecompiler(
	compiler *Compiler,
	codec configsync.SnapshotCodec[*readmodel.Snapshot],
	holder *Holder,
	notifier configsync.ChangeNotifier,
	logger *slog.Logger,
	cfg RecompilerConfig,
) *Recompiler {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Debounce <= 0 {
		cfg.Debounce = defaultDebounce
	}
	if cfg.Backstop <= 0 {
		cfg.Backstop = defaultBackstop
	}
	return &Recompiler{
		compiler: compiler,
		codec:    codec,
		holder:   holder,
		notifier: notifier,
		logger:   logger,
		debounce: cfg.Debounce,
		backstop: cfg.Backstop,
		trigger:  make(chan struct{}, 1),
	}
}

func (r *Recompiler) Signal() {
	select {
	case r.trigger <- struct{}{}:
	default:
	}
}

func (r *Recompiler) Run(ctx context.Context) error {
	if err := r.recompile(ctx); err != nil && ctx.Err() == nil {
		r.logger.Error("initial recompile failed",
			slog.String("component", component), slog.String("error", err.Error()))
	}

	timer := time.NewTimer(r.debounce)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()

	backstop := time.NewTicker(r.backstop)
	defer backstop.Stop()

	var armed bool
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.trigger:
			if !armed {
				timer.Reset(r.debounce)
				armed = true
			}
		case <-timer.C:
			armed = false
			if err := r.recompile(ctx); err != nil && ctx.Err() == nil {
				r.logger.Error("recompile failed",
					slog.String("component", component), slog.String("error", err.Error()))
			}
		case <-backstop.C:
			if err := r.recompile(ctx); err != nil && ctx.Err() == nil {
				r.logger.Error("backstop recompile failed",
					slog.String("component", component), slog.String("error", err.Error()))
			}
		}
	}
}

func (r *Recompiler) Recompile(ctx context.Context) error {
	return r.recompile(ctx)
}

func (r *Recompiler) recompile(ctx context.Context) error {
	snapshot, err := r.compiler.Compile(ctx)
	if err != nil {
		return fmt.Errorf("configsnapshot: compile: %w", err)
	}
	raw, err := r.codec.Encode(snapshot)
	if err != nil {
		return fmt.Errorf("configsnapshot: encode: %w", err)
	}
	version := r.codec.Version(raw)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.holder.Version() != version {
		r.holder.Set(raw, version)
	}
	if version == r.published {
		return nil
	}
	if _, err := r.notifier.Publish(ctx, version); err != nil {
		return fmt.Errorf("configsnapshot: publish version %s: %w", version, err)
	}
	r.published = version
	return nil
}
