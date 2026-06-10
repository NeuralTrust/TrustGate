package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	defaultFetchTimeout = 10 * time.Second
	// defaultRefreshInterval rate-limits forced refreshes (unknown kid or
	// signature failure) per URL so unauthenticated tokens with random kids
	// cannot amplify into outbound JWKS fetches.
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

// jwksFetch is the shared result of a single in-flight fetch: concurrent
// callers for the same URL wait on done instead of stampeding the endpoint.
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

// Refresh forces a fetch (key rotation suspected). Forced refreshes are
// rate-limited per URL: within the interval the cached set is served, even if
// its TTL elapsed, so attacker-crafted tokens cannot trigger fetch storms.
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

// awaitFetchLocked joins the in-flight fetch for the URL (starting one if
// needed) and waits for its shared result. It must be called with c.mu held
// and releases the lock before blocking.
func (c *JWKSCache) awaitFetchLocked(ctx context.Context, url string, entry *jwksEntry) (jwkSet, error) {
	fetch := entry.inflight
	if fetch == nil {
		fetch = &jwksFetch{done: make(chan struct{})}
		entry.inflight = fetch
		go c.runFetch(url, entry, fetch)
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
	keys, err := c.fetchRemote(url)
	c.mu.Lock()
	switch {
	case err == nil:
		entry.keys = keys
		entry.hasKeys = true
		entry.expiresAt = c.now().Add(c.ttl)
		fetch.keys = keys
	case entry.hasKeys:
		// Stale-while-error: a previously fetched set (even expired) beats
		// failing outright when the issuer endpoint is flaky.
		fetch.keys = entry.keys
	default:
		fetch.err = err
	}
	entry.inflight = nil
	c.mu.Unlock()
	close(fetch.done)
}

// fetchRemote deliberately uses a background context: the result is shared by
// every concurrent caller, so it must not be tied to any single caller's
// lifetime. The HTTP client timeout (10s default) bounds the request.
func (c *JWKSCache) fetchRemote(url string) (jwkSet, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
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
