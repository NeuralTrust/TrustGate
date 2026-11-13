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

package metrics

import (
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
)

// buildRetryInterval spaces out rebuilds of an exporter that failed to build,
// so a transient failure heals without every request paying for a rebuild.
const buildRetryInterval = time.Minute

type ExporterCache struct {
	factory ExporterFactory
	logger  *slog.Logger
	now     func() time.Time
	mu      sync.Mutex
	entries map[string]*cacheEntry
	// current maps an owned exporter's identity (gateway, origin, name) to
	// the key of the entry built for it, so a changed config, such as a
	// rotated credential, closes the exporter it replaces.
	current map[string]string
}

type cacheEntry struct {
	mu       sync.Mutex
	exporter Exporter
	retryAt  time.Time
}

func NewExporterCache(factory ExporterFactory, logger *slog.Logger) *ExporterCache {
	return &ExporterCache{
		factory: factory,
		logger:  logger,
		now:     time.Now,
		entries: make(map[string]*cacheEntry),
		current: make(map[string]string),
	}
}

// SourcedExporter is an exporter config together with who wrote it. A tenant's
// config must never reuse, or be built with the trust of, an identical operator
// one, so the two live under different cache keys.
type SourcedExporter struct {
	Config telemetrydomain.ExporterConfig
	Tenant bool
}

// Resolve builds the exporters for operator-written configs.
func (c *ExporterCache) Resolve(cfgs []telemetrydomain.ExporterConfig) []Exporter {
	items := make([]SourcedExporter, len(cfgs))
	for i, cfg := range cfgs {
		items[i] = SourcedExporter{Config: cfg}
	}
	return c.ResolveSourced(items)
}

// ResolveOwned is ResolveSourced for the exporters of one gateway: an
// exporter of owner whose config changed since the last call is closed once
// its replacement is resolved, instead of staying open for the process's
// life. An empty owner is ResolveSourced.
func (c *ExporterCache) ResolveOwned(owner string, items []SourcedExporter) []Exporter {
	out := c.ResolveSourced(items)
	if owner == "" {
		return out
	}
	for _, item := range items {
		if !item.Tenant {
			continue
		}
		key := "tenant\x00" + exporterCacheKey(item.Config)
		identity := owner + "\x00" + item.Config.Name
		c.mu.Lock()
		previous, had := c.current[identity]
		c.current[identity] = key
		var stale *cacheEntry
		if had && previous != key && !c.usedLocked(previous) {
			stale = c.entries[previous]
			delete(c.entries, previous)
		}
		c.mu.Unlock()
		if stale != nil {
			stale.mu.Lock()
			if stale.exporter != nil {
				stale.exporter.Close()
			}
			stale.mu.Unlock()
		}
	}
	return out
}

// usedLocked reports whether any owned exporter still resolves to key: two
// gateways with the same config share one exporter.
func (c *ExporterCache) usedLocked(key string) bool {
	for _, k := range c.current {
		if k == key {
			return true
		}
	}
	return false
}

// ResolveSourced builds the exporters for configs of mixed origin.
func (c *ExporterCache) ResolveSourced(items []SourcedExporter) []Exporter {
	out := make([]Exporter, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		key := exporterCacheKey(item.Config)
		if item.Tenant {
			key = "tenant\x00" + key
		}
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if exporter := c.get(key, item); exporter != nil {
			out = append(out, exporter)
		}
	}
	return out
}

func (c *ExporterCache) get(key string, item SourcedExporter) Exporter {
	cfg := item.Config
	c.mu.Lock()
	entry, ok := c.entries[key]
	if !ok {
		entry = &cacheEntry{}
		c.entries[key] = entry
	}
	c.mu.Unlock()

	entry.mu.Lock()
	defer entry.mu.Unlock()
	if entry.exporter != nil {
		return entry.exporter
	}
	now := c.now()
	if now.Before(entry.retryAt) {
		return nil
	}
	build := c.factory.Build
	if item.Tenant {
		build = c.factory.BuildTenant
	}
	exporter, err := build(cfg)
	if err != nil {
		entry.retryAt = now.Add(buildRetryInterval)
		c.logger.Warn("failed to build gateway exporter, skipping",
			slog.String("exporter", cfg.Name),
			slog.String("error", err.Error()),
			slog.Duration("retry_in", buildRetryInterval))
		return nil
	}
	entry.exporter = exporter
	return exporter
}

func (c *ExporterCache) CloseAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		entry.mu.Lock()
		if entry.exporter != nil {
			entry.exporter.Close()
		}
		entry.mu.Unlock()
		delete(c.entries, key)
	}
}

func exporterCacheKey(cfg telemetrydomain.ExporterConfig) string {
	data, err := json.Marshal(cfg)
	if err != nil {
		return cfg.Name
	}
	return string(data)
}
