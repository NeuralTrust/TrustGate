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

package configsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const component = "configsync"

const (
	defaultPollInterval = 5 * time.Minute
	defaultMinBackoff   = 1 * time.Second
	defaultMaxBackoff   = 30 * time.Second
)

type WorkerConfig struct {
	PollInterval time.Duration
	MinBackoff   time.Duration
	MaxBackoff   time.Duration
}

type Worker[T any] struct {
	fetcher      ConfigFetcher
	store        ConfigStore[T]
	notifier     ChangeNotifier
	lkg          *LKGStore[T]
	codec        SnapshotCodec[T]
	logger       *slog.Logger
	pollInterval time.Duration
	minBackoff   time.Duration
	maxBackoff   time.Duration
	convergeMu   sync.Mutex
}

func NewWorker[T any](
	fetcher ConfigFetcher,
	store ConfigStore[T],
	notifier ChangeNotifier,
	lkg *LKGStore[T],
	codec SnapshotCodec[T],
	logger *slog.Logger,
	cfg WorkerConfig,
) *Worker[T] {
	if logger == nil {
		logger = slog.Default()
	}
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = defaultPollInterval
	}
	minBackoff := cfg.MinBackoff
	if minBackoff <= 0 {
		minBackoff = defaultMinBackoff
	}
	maxBackoff := cfg.MaxBackoff
	if maxBackoff < minBackoff {
		maxBackoff = defaultMaxBackoff
	}
	if maxBackoff < minBackoff {
		maxBackoff = minBackoff
	}
	return &Worker[T]{
		fetcher:      fetcher,
		store:        store,
		notifier:     notifier,
		lkg:          lkg,
		codec:        codec,
		logger:       logger,
		pollInterval: pollInterval,
		minBackoff:   minBackoff,
		maxBackoff:   maxBackoff,
	}
}

func (w *Worker[T]) Run(ctx context.Context) error {
	w.restoreLKG()

	lastID, err := w.notifier.Tail(ctx)
	if err != nil {
		w.logger.Warn("failed to tail change stream",
			slog.String("component", component), slog.String("error", err.Error()))
		lastID = streamStart
	}

	if err := w.Converge(ctx); err != nil && ctx.Err() == nil {
		w.logger.Error("initial converge failed",
			slog.String("component", component), slog.String("error", err.Error()))
	}

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		w.watchLoop(ctx, lastID)
	}()
	go func() {
		defer wg.Done()
		w.backstopLoop(ctx)
	}()
	wg.Wait()
	return ctx.Err()
}

func (w *Worker[T]) Converge(ctx context.Context) error {
	w.convergeMu.Lock()
	defer w.convergeMu.Unlock()
	raw, version, notModified, err := w.fetcher.Fetch(ctx, w.store.Version())
	if err != nil {
		return fmt.Errorf("configsync: fetch snapshot: %w", err)
	}
	if notModified {
		return nil
	}
	if version == "" {
		return fmt.Errorf("%w: snapshot response has no version", ErrIntegrity)
	}
	if computed := w.codec.Version(raw); version != computed {
		return fmt.Errorf("%w: etag %q != body sha256 %q", ErrIntegrity, version, computed)
	}
	snapshot, err := w.codec.Decode(raw)
	if err != nil {
		return fmt.Errorf("configsync: decode snapshot: %w", err)
	}
	versioned := &Versioned[T]{Version: version, Snapshot: snapshot, Raw: raw}
	w.store.Swap(versioned)
	w.persist(versioned)
	return nil
}

func (w *Worker[T]) restoreLKG() {
	if w.lkg == nil {
		return
	}
	v, err := w.lkg.Load()
	if err != nil {
		if errors.Is(err, ErrLKGCorrupt) {
			w.logger.Warn("discarding corrupt last-known-good snapshot",
				slog.String("component", component), slog.String("error", err.Error()))
			return
		}
		w.logger.Warn("failed to load last-known-good snapshot",
			slog.String("component", component), slog.String("error", err.Error()))
		return
	}
	if v != nil {
		w.store.Swap(v)
	}
}

func (w *Worker[T]) persist(v *Versioned[T]) {
	if w.lkg == nil {
		return
	}
	if err := w.lkg.Persist(v); err != nil {
		w.logger.Warn("failed to persist last-known-good snapshot",
			slog.String("component", component), slog.String("error", err.Error()))
	}
}

func (w *Worker[T]) watchLoop(ctx context.Context, lastID string) {
	backoff := w.minBackoff
	for {
		if ctx.Err() != nil {
			return
		}
		id, _, err := w.notifier.Watch(ctx, lastID)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			w.logger.Error("change stream watch failed",
				slog.String("component", component), slog.String("error", err.Error()))
			if !sleep(ctx, backoff) {
				return
			}
			backoff = nextBackoff(backoff, w.maxBackoff)
			continue
		}
		backoff = w.minBackoff
		if id == "" {
			continue
		}
		lastID = id
		if err := w.Converge(ctx); err != nil && ctx.Err() == nil {
			w.logger.Error("converge after notification failed",
				slog.String("component", component), slog.String("error", err.Error()))
		}
	}
}

func (w *Worker[T]) backstopLoop(ctx context.Context) {
	ticker := time.NewTicker(w.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := w.Converge(ctx); err != nil && ctx.Err() == nil {
				w.logger.Error("backstop converge failed",
					slog.String("component", component), slog.String("error", err.Error()))
			}
		}
	}
}

func sleep(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}
