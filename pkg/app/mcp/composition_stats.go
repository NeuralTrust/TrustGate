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

package mcp

import (
	"context"
	"sync/atomic"
)

type compositionStatsKey struct{}

// compositionStats reports whether the compositions run under one context saw
// every registry bound to the consumer. Federation is fail-open, so a skipped
// registry yields a smaller surface with no error, which a caller diffing
// successive compositions cannot tell apart from a genuine removal (RUN-1104 D6).
type compositionStats struct {
	degraded atomic.Bool
}

// Degraded reports whether any composition run under the context skipped a bound
// registry, making the composed surface narrower than the consumer's real one.
func (s *compositionStats) Degraded() bool {
	return s != nil && s.degraded.Load()
}

// withCompositionStats returns a child context the composer reports skipped
// registries on, together with the collector to read once the compositions have
// returned. Callers that install no collector pay nothing.
func withCompositionStats(ctx context.Context) (context.Context, *compositionStats) {
	stats := &compositionStats{}
	return context.WithValue(ctx, compositionStatsKey{}, stats), stats
}

func markCompositionDegraded(ctx context.Context) {
	stats, ok := ctx.Value(compositionStatsKey{}).(*compositionStats)
	if !ok {
		return
	}
	stats.degraded.Store(true)
}
