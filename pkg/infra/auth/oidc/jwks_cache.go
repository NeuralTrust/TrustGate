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

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	defaultFetchTimeout    = 10 * time.Second
	defaultRefreshInterval = 30 * time.Second
)

type JWKSCache struct {
	client          *http.Client
	ttl             time.Duration
	refreshInterval time.Duration
	now             func() time.Time
	mu              sync.Mutex
	items           map[string]*jwksEntry
}

type jwksEntry struct {
	keys           jwkSet
	hasKeys        bool
	expiresAt      time.Time
	lastForcedAt   time.Time
	hasForcedFetch bool
	inflight       *jwksFetch
}

type jwksFetch struct {
	done chan struct{}
	keys jwkSet
	err  error
}

func NewJWKSCache(client *http.Client, ttl time.Duration) *JWKSCache {
	if client == nil {
		client = &http.Client{Timeout: defaultFetchTimeout}
	} else if client.Timeout <= 0 {
		clone := *client
		clone.Timeout = defaultFetchTimeout
		client = &clone
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &JWKSCache{
		client:          client,
		ttl:             ttl,
		refreshInterval: defaultRefreshInterval,
		now:             time.Now,
		items:           make(map[string]*jwksEntry),
	}
}

func (c *JWKSCache) Get(ctx context.Context, url string) (jwkSet, error) {
	c.mu.Lock()
	entry := c.entryLocked(url)
	if entry.hasKeys && c.now().Before(entry.expiresAt) {
		keys := entry.keys
		c.mu.Unlock()
		return keys, nil
	}
	return c.awaitFetchLocked(ctx, url, entry)
}

func (c *JWKSCache) Refresh(ctx context.Context, url string) (jwkSet, error) {
	c.mu.Lock()
	entry := c.entryLocked(url)
	now := c.now()
	if entry.hasKeys && entry.hasForcedFetch && now.Sub(entry.lastForcedAt) < c.refreshInterval {
		keys := entry.keys
		c.mu.Unlock()
		return keys, nil
	}
	entry.lastForcedAt = now
	entry.hasForcedFetch = true
	return c.awaitFetchLocked(ctx, url, entry)
}

func (c *JWKSCache) entryLocked(url string) *jwksEntry {
	entry, ok := c.items[url]
	if !ok {
		entry = &jwksEntry{}
		c.items[url] = entry
	}
	return entry
}

func (c *JWKSCache) awaitFetchLocked(ctx context.Context, url string, entry *jwksEntry) (jwkSet, error) {
	fetch := entry.inflight
	if fetch == nil {
		fetch = &jwksFetch{done: make(chan struct{})}
		entry.inflight = fetch
		go c.runFetch(url, entry, fetch) // #nosec G118 -- shared fetch must not adopt a single caller's context; runFetch owns its own timeout
	}
	c.mu.Unlock()
	select {
	case <-fetch.done:
		return fetch.keys, fetch.err
	case <-ctx.Done():
		return jwkSet{}, fmt.Errorf("%w: %v", ErrJWKSFetch, ctx.Err())
	}
}

func (c *JWKSCache) runFetch(url string, entry *jwksEntry, fetch *jwksFetch) {
	// The fetch is shared across awaiting callers, so it must not adopt any
	// single caller's context; it owns a timeout so an in-flight request cannot
	// outlive an explicit bound.
	ctx, cancel := context.WithTimeout(context.Background(), c.fetchTimeout())
	defer cancel()
	keys, err := c.fetchRemote(ctx, url)
	c.mu.Lock()
	switch {
	case err == nil:
		entry.keys = keys
		entry.hasKeys = true
		entry.expiresAt = c.now().Add(c.ttl)
		fetch.keys = keys
	case entry.hasKeys:
		fetch.keys = entry.keys
	default:
		fetch.err = err
	}
	entry.inflight = nil
	c.mu.Unlock()
	close(fetch.done)
}

func (c *JWKSCache) fetchTimeout() time.Duration {
	if c.client != nil && c.client.Timeout > 0 {
		return c.client.Timeout
	}
	return defaultFetchTimeout
}

func (c *JWKSCache) fetchRemote(ctx context.Context, url string) (jwkSet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return jwkSet{}, fmt.Errorf("%w: build jwks request: %v", ErrJWKSFetch, err)
	}
	resp, err := c.client.Do(req)
	if err != nil {
		return jwkSet{}, fmt.Errorf("%w: fetch jwks: %v", ErrJWKSFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return jwkSet{}, fmt.Errorf("%w: jwks status %d", ErrJWKSFetch, resp.StatusCode)
	}
	var keys jwkSet
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return jwkSet{}, fmt.Errorf("%w: decode jwks: %v", ErrJWKSFetch, err)
	}
	return keys, nil
}
