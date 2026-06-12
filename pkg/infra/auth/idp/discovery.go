package idp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

const discoveryTTL = time.Hour

type discovery struct {
	client *http.Client
	sf     singleflight.Group

	mu      sync.Mutex
	entries map[string]discoveryEntry
}

type discoveryEntry struct {
	jwksURI   string
	fetchedAt time.Time
}

func newDiscovery(client *http.Client) *discovery {
	if client == nil {
		client = &http.Client{Timeout: defaultFetchTimeout}
	}
	return &discovery{client: client, entries: map[string]discoveryEntry{}}
}

func (d *discovery) jwksURI(ctx context.Context, issuer string) (string, error) {
	d.mu.Lock()
	if e, ok := d.entries[issuer]; ok && time.Since(e.fetchedAt) < discoveryTTL {
		d.mu.Unlock()
		return e.jwksURI, nil
	}
	d.mu.Unlock()

	v, err, _ := d.sf.Do(issuer, func() (any, error) {
		return d.fetch(ctx, issuer)
	})
	if err != nil {
		return "", err
	}
	uri, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("oidc discovery: unexpected singleflight result type")
	}
	return uri, nil
}

func (d *discovery) fetch(ctx context.Context, issuer string) (string, error) {
	url := strings.TrimSuffix(issuer, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("oidc discovery: build request: %w", err)
	}
	res, err := d.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc discovery %s: %w", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc discovery %s: status %d", url, res.StatusCode)
	}
	var doc struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return "", fmt.Errorf("oidc discovery %s: decode: %w", url, err)
	}
	if doc.JWKSURI == "" {
		return "", fmt.Errorf("oidc discovery %s: no jwks_uri", url)
	}
	d.mu.Lock()
	d.entries[issuer] = discoveryEntry{jwksURI: doc.JWKSURI, fetchedAt: time.Now()}
	d.mu.Unlock()
	return doc.JWKSURI, nil
}
