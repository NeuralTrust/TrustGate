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

	telemetrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/telemetry"
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

func (c *ExporterCache) Resolve(cfgs []telemetrydomain.ExporterConfig) []Exporter {
	out := make([]Exporter, 0, len(cfgs))
	seen := make(map[string]struct{}, len(cfgs))
	for _, cfg := range cfgs {
		key := exporterCacheKey(cfg)
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		if exporter := c.get(key, cfg); exporter != nil {
			out = append(out, exporter)
		}
	}
	return out
}

func (c *ExporterCache) get(key string, cfg telemetrydomain.ExporterConfig) Exporter {
	c.mu.Lock()
	entry, ok := c.entries[key]
	if !ok {
		entry = &cacheEntry{}
		c.entries[key] = entry
	}
	c.mu.Unlock()

	entry.once.Do(func() {
		exporter, err := c.factory.Build(cfg)
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
