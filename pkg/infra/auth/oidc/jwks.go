package oidc

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

var ErrKeyNotFound = errors.New("oidc: signing key not found")

const (
	jwksTTL    = time.Hour
	minRefresh = 30 * time.Second
)

type JWKSCache struct {
	client *http.Client

	sf   singleflight.Group
	mu   sync.Mutex
	sets map[string]*keySet
}

type keySet struct {
	keys      map[string]crypto.PublicKey
	fetchedAt time.Time
}

func NewJWKSCache(client *http.Client) *JWKSCache {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &JWKSCache{client: client, sets: map[string]*keySet{}}
}

func (c *JWKSCache) Key(ctx context.Context, url, kid string) (crypto.PublicKey, error) {
	c.mu.Lock()
	set := c.sets[url]
	if set != nil && time.Since(set.fetchedAt) < jwksTTL {
		if key, ok := set.keys[kid]; ok {
			c.mu.Unlock()
			return key, nil
		}
		if time.Since(set.fetchedAt) < minRefresh {
			c.mu.Unlock()
			return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
		}
	}
	c.mu.Unlock()

	// Coalesce concurrent refreshes of the same JWKS URL so a burst of
	// requests with an unknown kid produces a single upstream fetch.
	v, err, _ := c.sf.Do(url, func() (any, error) {
		fresh, err := c.fetch(ctx, url)
		if err != nil {
			return nil, err
		}
		c.mu.Lock()
		c.sets[url] = fresh
		c.mu.Unlock()
		return fresh, nil
	})
	if err != nil {
		return nil, err
	}
	fresh, ok := v.(*keySet)
	if !ok {
		return nil, errors.New("oidc: unexpected singleflight result type")
	}
	if key, ok := fresh.keys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: kid %q", ErrKeyNotFound, kid)
}

func (c *JWKSCache) fetch(ctx context.Context, url string) (*keySet, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("oidc: build jwks request: %w", err)
	}
	res, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch jwks %s: %w", url, err)
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("oidc: fetch jwks %s: status %d", url, res.StatusCode)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(res.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("oidc: decode jwks %s: %w", url, err)
	}
	set := &keySet{keys: map[string]crypto.PublicKey{}, fetchedAt: time.Now()}
	for _, k := range doc.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		key, err := k.publicKey()
		if err != nil {
			continue // skip unsupported entries; other keys may still verify
		}
		set.keys[k.Kid] = key
	}
	return set, nil
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

func (k jwk) publicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk rsa n: %w", err)
		}
		e, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk rsa e: %w", err)
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	case "EC":
		curve, err := curveFor(k.Crv)
		if err != nil {
			return nil, err
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk ec x: %w", err)
		}
		y, err := base64.RawURLEncoding.DecodeString(k.Y)
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk ec y: %w", err)
		}
		return &ecdsa.PublicKey{
			Curve: curve,
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		}, nil
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("oidc: unsupported okp curve %q", k.Crv)
		}
		x, err := base64.RawURLEncoding.DecodeString(k.X)
		if err != nil {
			return nil, fmt.Errorf("oidc: jwk okp x: %w", err)
		}
		return ed25519.PublicKey(x), nil
	default:
		return nil, fmt.Errorf("oidc: unsupported jwk kty %q", k.Kty)
	}
}

func curveFor(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("oidc: unsupported ec curve %q", crv)
	}
}
