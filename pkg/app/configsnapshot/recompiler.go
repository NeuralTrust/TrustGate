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

	"github.com/NeuralTrust/TrustGate/pkg/configsnapshot/readmodel"
	"github.com/NeuralTrust/TrustGate/pkg/configsync"
)

const component = "configsnapshot"

const defaultDebounce = 2 * time.Second

type snapshotCompiler interface {
	Compile(ctx context.Context) (*readmodel.Snapshot, error)
}

type Recompiler struct {
	compiler snapshotCompiler
	codec    configsync.SnapshotCodec[*readmodel.Snapshot]
	holder   *Holder
	notifier configsync.ChangeNotifier
	logger   *slog.Logger
	debounce time.Duration
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
	debounce time.Duration,
) *Recompiler {
	if logger == nil {
		logger = slog.Default()
	}
	if debounce <= 0 {
		debounce = defaultDebounce
	}
	return &Recompiler{
		compiler: compiler,
		codec:    codec,
		holder:   holder,
		notifier: notifier,
		logger:   logger,
		debounce: debounce,
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
