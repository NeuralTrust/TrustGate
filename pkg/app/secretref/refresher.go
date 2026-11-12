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

package secretref

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

// Run probes the stores at once, then refreshes cached payloads every
// refresh interval and probes every probe interval until ctx is done. Each
// round finishes before the next starts and before Run returns.
func (c *Cache) Run(ctx context.Context) {
	c.probeTick(ctx)
	refresh := time.NewTicker(c.refreshInterval)
	defer refresh.Stop()
	probe := time.NewTicker(c.probeInterval)
	defer probe.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-refresh.C:
			c.refreshTick(ctx)
		case <-probe.C:
			c.probeTick(ctx)
		}
	}
}

type dueFetch struct {
	key   string
	entry *entry
}

// refreshTick evicts payloads nobody resolved within the idle window, withdraws values
// past their stale window, and re-reads every payload that is due: values from
// 80 % of their TTL (with per-entry jitter) and failures once their backoff
// or negative TTL ran out, so a recovered store reaches dependents that were
// built without the value.
func (c *Cache) refreshTick(ctx context.Context) {
	now := c.now()
	var expired []domain.Ref
	var due []dueFetch

	c.mu.Lock()
	for key, e := range c.entries {
		if now.Sub(e.lastUsed) >= c.idleEviction {
			// Data built from the value may still be cached by its readers;
			// once nothing refreshes it, they must resolve it again.
			if e.hasValue {
				expired = append(expired, e.payload)
			}
			delete(c.entries, key)
			c.flights.Forget(key)
			continue
		}
		if e.expire(now) {
			expired = append(expired, e.payload)
		}
		if e.due(now) {
			due = append(due, dueFetch{key: key, entry: e})
		}
	}
	c.mu.Unlock()
	c.notify(expired)

	g := new(errgroup.Group)
	g.SetLimit(refreshConcurrency)
	for _, d := range due {
		_, backend, ok := c.catalog.Get(d.entry.payload.Store)
		if !ok {
			continue
		}
		g.Go(func() error {
			_, _ = c.fetch(ctx, d.key, d.entry, backend) // the outcome is recorded on the entry and in metrics
			return nil
		})
	}
	_ = g.Wait() // the goroutines never return an error
}
