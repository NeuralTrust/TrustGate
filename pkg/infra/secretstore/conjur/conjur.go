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

// Package conjur reads CyberArk Conjur variables over its REST API. The plane
// authenticates with authn-jwt (the projected ServiceAccount token by
// default) or with a host's API key read from a mounted Secret, and renews
// the short-lived access token before it expires.
package conjur

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/internal/httpclient"
)

// tokenRefreshAfter is two thirds of the 8 minutes a Conjur access token
// lives.
const tokenRefreshAfter = 320 * time.Second

// Backend reads the variables of one Conjur account.
type Backend struct {
	cfg      *secretstore.CyberArkConjurConfig
	base     string
	client   *http.Client
	now      func() time.Time
	readFile func(string) ([]byte, error)

	// login holds one slot: one authentication runs at a time, and a caller
	// waiting for it gives up when its context ends.
	login chan struct{}

	mu       sync.Mutex
	token    string
	issuedAt time.Time
}

var _ secretstore.Backend = (*Backend)(nil)

// New returns the backend for cfg.
func New(cfg *secretstore.CyberArkConjurConfig) (*Backend, error) {
	client, err := httpclient.New(cfg.CACertFile)
	if err != nil {
		return nil, err
	}
	return &Backend{
		cfg: cfg, base: strings.TrimRight(cfg.URL, "/"), client: client,
		now: time.Now, readFile: os.ReadFile, login: make(chan struct{}, 1),
	}, nil
}

// Fetch implements secretstore.Backend. The path is a variable id and the
// version a variable version, the latest by default.
func (b *Backend) Fetch(ctx context.Context, path, version string) (secretstore.Secret, error) {
	target := b.base + "/secrets/" + url.PathEscape(b.cfg.Account) + "/variable/" + url.PathEscape(path)
	if version != "" {
		n, err := strconv.Atoi(version)
		if err != nil || n <= 0 {
			return secretstore.Secret{}, fmt.Errorf("%w: a Conjur variable version is a positive integer", secretstore.ErrInvalidPayload)
		}
		target += "?" + url.Values{"version": {strconv.Itoa(n)}}.Encode()
	}
	token, err := b.ensureToken(ctx)
	if err != nil {
		return secretstore.Secret{}, err
	}
	resp, err := b.get(ctx, target, token)
	if err != nil {
		return secretstore.Secret{}, err
	}
	if resp.StatusCode == http.StatusUnauthorized {
		// The token expired or was revoked early: authenticate once more.
		httpclient.Discard(resp)
		b.dropToken(token)
		if token, err = b.ensureToken(ctx); err != nil {
			return secretstore.Secret{}, err
		}
		if resp, err = b.get(ctx, target, token); err != nil {
			return secretstore.Secret{}, err
		}
	}
	if resp.StatusCode != http.StatusOK {
		httpclient.Discard(resp)
		return secretstore.Secret{}, httpclient.StatusError(resp.StatusCode)
	}
	raw, err := httpclient.ReadBody(resp)
	if err != nil {
		return secretstore.Secret{}, err
	}
	if !utf8.Valid(raw) {
		return secretstore.Secret{}, fmt.Errorf("%w: the variable is binary", secretstore.ErrInvalidPayload)
	}
	return secretstore.NewStringSecret(string(raw), version), nil
}

// Probe implements secretstore.Backend: the plane can authenticate, without
// reading any variable.
func (b *Backend) Probe(ctx context.Context) error {
	_, err := b.ensureToken(ctx)
	return err
}

func (b *Backend) get(ctx context.Context, target, token string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: building the request", secretstore.ErrInvalidPayload)
	}
	req.Header.Set("Authorization", `Token token="`+token+`"`)
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, httpclient.TransportError(err)
	}
	return resp, nil
}

func (b *Backend) currentToken() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.token == "" || b.now().Sub(b.issuedAt) >= tokenRefreshAfter {
		return "", false
	}
	return b.token, true
}

func (b *Backend) dropToken(used string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.token == used {
		b.token = ""
	}
}

// ensureToken returns a usable access token, authenticating when the
// current one is missing or past two thirds of its life.
func (b *Backend) ensureToken(ctx context.Context) (string, error) {
	if token, ok := b.currentToken(); ok {
		return token, nil
	}
	select {
	case b.login <- struct{}{}:
	case <-ctx.Done():
		return "", fmt.Errorf("%w: waiting for another authentication to the store: %v", secretstore.ErrUnavailable, ctx.Err())
	}
	defer func() { <-b.login }()
	if token, ok := b.currentToken(); ok {
		return token, nil
	}
	token, err := b.authenticate(ctx)
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	b.token, b.issuedAt = token, b.now()
	b.mu.Unlock()
	return token, nil
}

// authenticate exchanges the configured credential for an access token,
// returned base64-encoded as the Authorization header carries it.
func (b *Backend) authenticate(ctx context.Context) (string, error) {
	account := url.PathEscape(b.cfg.Account)
	var target, body, contentType string
	switch b.cfg.Auth.EffectiveMethod() {
	case secretstore.ConjurAuthAPIKey:
		key, err := b.credential(b.cfg.Auth.APIKeyFile)
		if err != nil {
			return "", err
		}
		target = b.base + "/authn/" + account + "/" + url.PathEscape(b.cfg.Auth.Login) + "/authenticate"
		body, contentType = key, "text/plain"
	default:
		jwt, err := b.credential(b.cfg.Auth.EffectiveJWTFile())
		if err != nil {
			return "", err
		}
		target = b.base + "/authn-jwt/" + url.PathEscape(b.cfg.Auth.ServiceID) + "/" + account + "/authenticate"
		body, contentType = url.Values{"jwt": {jwt}}.Encode(), "application/x-www-form-urlencoded"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, strings.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%w: building the request", secretstore.ErrInvalidPayload)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept-Encoding", "base64")
	resp, err := b.client.Do(req)
	if err != nil {
		return "", httpclient.TransportError(err)
	}
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized, http.StatusForbidden:
		httpclient.Discard(resp)
		return "", fmt.Errorf("%w: the store refused the credential (%d)", secretstore.ErrAuthFailed, resp.StatusCode)
	default:
		httpclient.Discard(resp)
		return "", httpclient.StatusError(resp.StatusCode)
	}
	raw, err := httpclient.ReadBody(resp)
	if err != nil {
		return "", err
	}
	token := strings.TrimSpace(string(raw))
	if strings.HasPrefix(token, "{") {
		// A server that ignores Accept-Encoding answers the JSON token.
		token = base64.StdEncoding.EncodeToString([]byte(token))
	}
	if token == "" {
		return "", fmt.Errorf("%w: the store returned no access token", secretstore.ErrAuthFailed)
	}
	return token, nil
}

func (b *Backend) credential(path string) (string, error) {
	raw, err := b.readFile(path)
	if err != nil {
		return "", fmt.Errorf("%w: the credential file is not readable", secretstore.ErrAuthFailed)
	}
	value := strings.TrimSpace(string(raw))
	if value == "" {
		return "", fmt.Errorf("%w: the credential file is empty", secretstore.ErrAuthFailed)
	}
	return value, nil
}
