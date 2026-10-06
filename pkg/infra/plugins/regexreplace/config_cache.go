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

package regexreplace

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
)

// maxCachedConfigs bounds the cache. Entries are keyed by the digest of a
// stored policy's settings, so the number in play is the number of regex
// policies a process serves; past the bound the cache is dropped rather than
// grown, which costs a re-parse and nothing else.
const maxCachedConfigs = 512

// configCache holds parsed settings so the regexes are compiled once per
// distinct policy instead of per streamed request and per block. A parsed
// Settings is immutable after parseConfig, so sharing it is safe.
type configCache struct {
	mu      sync.RWMutex
	entries map[string]Settings
}

func (c *configCache) load(key string) (Settings, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	cfg, ok := c.entries[key]
	return cfg, ok
}

func (c *configCache) store(key string, cfg Settings) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.entries == nil || len(c.entries) >= maxCachedConfigs {
		c.entries = make(map[string]Settings)
	}
	c.entries[key] = cfg
}

// config parses settings, once per distinct settings map. Failures are not
// cached, so a policy that does not parse keeps reporting why.
func (p *Plugin) config(settings map[string]any) (Settings, error) {
	raw, err := json.Marshal(settings)
	if err != nil {
		return parseConfig(settings)
	}
	sum := sha256.Sum256(raw)
	key := hex.EncodeToString(sum[:])
	if cfg, ok := p.cfgCache.load(key); ok {
		return cfg, nil
	}
	cfg, err := parseConfig(settings)
	if err != nil {
		return Settings{}, err
	}
	p.cfgCache.store(key, cfg)
	return cfg, nil
}
