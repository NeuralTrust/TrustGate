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

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
)

type ExporterCache struct {
	factory ExporterFactory
	logger  *slog.Logger
	mu      sync.Mutex
	entries map[string]*cacheEntry
}

type cacheEntry struct {
	once     sync.Once
	exporter Exporter
}

func NewExporterCache(factory ExporterFactory, logger *slog.Logger) *ExporterCache {
	return &ExporterCache{
		factory: factory,
		logger:  logger,
		entries: make(map[string]*cacheEntry),
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

	entry.once.Do(func() {
		build := c.factory.Build
		if item.Tenant {
			build = c.factory.BuildTenant
		}
		exporter, err := build(cfg)
		if err != nil {
			c.logger.Warn("failed to build gateway exporter, skipping",
				slog.String("exporter", cfg.Name),
				slog.String("error", err.Error()))
			return
		}
		entry.exporter = exporter
	})
	return entry.exporter
}

func (c *ExporterCache) CloseAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for key, entry := range c.entries {
		if entry.exporter != nil {
			entry.exporter.Close()
		}
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
