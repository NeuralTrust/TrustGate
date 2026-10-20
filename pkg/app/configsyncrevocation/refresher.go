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

package configsyncrevocation

import (
	"context"
	"log/slog"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/configsyncrevocation"
)

const (
	// primeLoadTimeout bounds the boot load, which runs before the listeners
	// serve, so a slow store delays startup by seconds at most.
	primeLoadTimeout = 3 * time.Second
	// maxLoadTimeout bounds one periodic reload so a stuck query cannot
	// overlap the next tick.
	maxLoadTimeout = 10 * time.Second
)

//go:generate mockery --name=StreamCloser --dir=. --output=./mocks --filename=configsyncrevocation_stream_closer_mock.go --case=underscore --with-expecter

// StreamCloser ends the open config-sync streams whose token matches.
type StreamCloser interface {
	// CloseRevoked closes every open stream whose verified token satisfies
	// isRevoked and returns how many it closed.
	CloseRevoked(isRevoked func(domain.Identity) bool) int
}

//go:generate mockery --name=Refresher --dir=. --output=./mocks --filename=configsyncrevocation_refresher_mock.go --case=underscore --with-expecter

// Refresher keeps the gate's snapshot in step with the stored revocations.
// Control replicas do not notify each other, so every replica reloads on its
// own interval.
type Refresher interface {
	// Prime loads once, synchronously. A failure leaves the gate empty, so
	// the control channel keeps serving while the store is unreachable.
	Prime(ctx context.Context)
	// Run reloads every interval until ctx is cancelled.
	Run(ctx context.Context)
}

var _ Refresher = (*refresher)(nil)

type refresher struct {
	store    domain.Store
	gate     Gate
	closer   StreamCloser
	interval time.Duration
	logger   *slog.Logger
}

// NewRefresher returns a refresher that loads store into gate every interval.
// In enforce mode, each successful load also closes, through closer, the open
// streams whose token is now revoked.
func NewRefresher(store domain.Store, gate Gate, closer StreamCloser, interval time.Duration, logger *slog.Logger) Refresher {
	if logger == nil {
		logger = slog.Default()
	}
	return &refresher{store: store, gate: gate, closer: closer, interval: interval, logger: logger}
}

func (r *refresher) Prime(ctx context.Context) {
	if r.gate.Mode() == ModeOff {
		return
	}
	r.refresh(ctx, min(r.interval, primeLoadTimeout))
}

func (r *refresher) Run(ctx context.Context) {
	if r.gate.Mode() == ModeOff {
		return
	}
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refresh(ctx, min(r.interval, maxLoadTimeout))
		}
	}
}

func (r *refresher) refresh(ctx context.Context, timeout time.Duration) {
	loadCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	loaded, err := r.store.Load(loadCtx)
	if err != nil {
		if ctx.Err() != nil {
			return
		}
		recordRefresh(ctx, refreshError)
		r.logger.ErrorContext(ctx, "config-sync revocation reload failed; keeping the last loaded set",
			slog.String("component", component),
			slog.String("error", err.Error()))
		return
	}
	snapshot := domain.NewSnapshot(loaded)
	r.gate.Replace(snapshot)
	recordRefresh(ctx, refreshOK)
	if r.gate.Mode() != ModeEnforce {
		return
	}
	if closed := r.closer.CloseRevoked(r.gate.Revoked); closed > 0 {
		recordStreamsClosed(ctx, closed)
		r.logger.WarnContext(ctx, "closed config-sync streams whose token is revoked",
			slog.String("component", component),
			slog.Int("streams", closed))
	}
}
