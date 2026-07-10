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

package cache

import (
	"context"
	"sync"
	"time"
)

const JanitorInterval = 1 * time.Minute

const (
	GatewayTTLName      = "gateway"
	RegistryTTLName     = "backend"
	ConsumerTTLName     = "consumer"
	RoleTTLName         = "role"
	ConsumerDataTTLName = "consumer_data"
	PolicyTTLName       = "policy"
	AuthTTLName         = "auth"
	AuthKeyTTLName      = "auth_key"
	LoadBalancerTTLName = "lb"
	// CatalogModelTTLName indexes catalog models by "providerCode:slug" for the
	// proxy plane's cost computation, so pricing avoids a DB round-trip on the
	// hot path after the first lookup.
	CatalogModelTTLName = "catalog_model"
	ConsumerPathTTLName = "consumer_path"
	MCPToolsTTLName     = "mcp_tools"
)

const (
	GatewayCacheTTL      = 1 * time.Hour
	RegistryCacheTTL     = 5 * time.Minute
	ConsumerCacheTTL     = 5 * time.Minute
	RoleCacheTTL         = 5 * time.Minute
	ConsumerDataCacheTTL = 1 * time.Hour
	PolicyCacheTTL       = 5 * time.Minute
	AuthCacheTTL         = 5 * time.Minute
	AuthKeyCacheTTL      = 5 * time.Minute
	LoadBalancerCacheTTL = 5 * time.Minute
	CatalogModelCacheTTL = 24 * time.Hour
	MCPToolsCacheTTL     = 5 * time.Minute
)

type TTLMapManager struct {
	mu         sync.Mutex
	maps       map[string]*TTLMap
	defaultTTL time.Duration
}

func NewTTLMapManager(defaultTTL time.Duration) *TTLMapManager {
	return &TTLMapManager{
		maps:       make(map[string]*TTLMap),
		defaultTTL: defaultTTL,
	}
}

func (m *TTLMapManager) GetTTLMap(name string) *TTLMap {
	m.mu.Lock()
	defer m.mu.Unlock()
	if cached, ok := m.maps[name]; ok {
		return cached
	}
	tm := NewTTLMap(m.defaultTTL)
	m.maps[name] = tm
	return tm
}

func (m *TTLMapManager) CreateTTLMap(name string, ttl time.Duration) *TTLMap {
	m.mu.Lock()
	defer m.mu.Unlock()
	tm := NewTTLMap(ttl)
	m.maps[name] = tm
	return tm
}

func (m *TTLMapManager) ClearAllTTLMaps() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tm := range m.maps {
		tm.Clear()
	}
}

func (m *TTLMapManager) DefaultTTL() time.Duration { return m.defaultTTL }

func (m *TTLMapManager) StartJanitor(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = JanitorInterval
	}
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				m.sweep(now)
			}
		}
	}()
}

func (m *TTLMapManager) sweep(now time.Time) {
	m.mu.Lock()
	maps := make([]*TTLMap, 0, len(m.maps))
	for _, tm := range m.maps {
		maps = append(maps, tm)
	}
	m.mu.Unlock()
	for _, tm := range maps {
		tm.sweepExpired(now)
	}
}
