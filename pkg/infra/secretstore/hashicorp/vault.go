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

// Package hashicorp reads the KV secrets engine of HashiCorp Vault and
// OpenBao over their HTTP API.
package hashicorp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/internal/httpclient"
)

// reloginGap is the shortest time between two logins forced by denied
// reads, so a burst of reads of denied paths does not become a burst of
// logins.
const reloginGap = 10 * time.Second

// Backend reads one KV mount. It logs in lazily, renews its token at two
// thirds of the lease, and logs in again when renewal fails or a read is
// denied. Credential files are read again on every login, since the
// platform rotates them.
type Backend struct {
	cfg      *secretstore.HashiCorpVaultConfig
	base     *url.URL
	client   *http.Client
	now      func() time.Time
	readFile func(string) ([]byte, error)

	loginMu sync.Mutex

	mu        sync.Mutex
	token     string
	renewable bool
	issuedAt  time.Time
	lease     time.Duration
	lastLogin time.Time
}

var _ secretstore.Backend = (*Backend)(nil)

// New returns the backend for cfg.
func New(cfg *secretstore.HashiCorpVaultConfig) (*Backend, error) {
	base, err := url.Parse(strings.TrimRight(cfg.Address, "/"))
	if err != nil {
		return nil, fmt.Errorf("%w: hashicorp_vault.address: %v", secretstore.ErrInvalidStore, err)
	}
	client, err := httpclient.New(cfg.CACertFile)
	if err != nil {
		return nil, err
	}
	return &Backend{cfg: cfg, base: base, client: client, now: time.Now, readFile: os.ReadFile}, nil
}

// Fetch implements secretstore.Backend.
func (b *Backend) Fetch(ctx context.Context, path, version string) (secretstore.Secret, error) {
	target, err := b.readURL(path, version)
	if err != nil {
		return secretstore.Secret{}, err
	}
	token, err := b.ensureToken(ctx)
	if err != nil {
		return secretstore.Secret{}, err
	}
	resp, err := b.do(ctx, http.MethodGet, target, token, nil)
	if err != nil {
		return secretstore.Secret{}, err
	}
	if resp.StatusCode == http.StatusForbidden {
		httpclient.Discard(resp)
		fresh, err := b.reloginAfterDenied(ctx, token)
		if err != nil {
			return secretstore.Secret{}, err
		}
		if fresh == "" {
			return secretstore.Secret{}, httpclient.StatusError(http.StatusForbidden)
		}
		if resp, err = b.do(ctx, http.MethodGet, target, fresh, nil); err != nil {
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
	return b.decode(raw)
}

// Probe implements secretstore.Backend: the plane can log in and its token
// is accepted, without reading any secret.
func (b *Backend) Probe(ctx context.Context) error {
	token, err := b.ensureToken(ctx)
	if err != nil {
		return err
	}
	resp, err := b.do(ctx, http.MethodGet, b.endpoint("auth", "token", "lookup-self"), token, nil)
	if err != nil {
		return err
	}
	httpclient.Discard(resp)
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusUnauthorized, http.StatusForbidden:
		b.dropToken(token)
		return fmt.Errorf("%w: the store answered %d to a token lookup", secretstore.ErrAuthFailed, resp.StatusCode)
	default:
		return httpclient.StatusError(resp.StatusCode)
	}
}

func (b *Backend) readURL(path, version string) (string, error) {
	segments := strings.Split(path, "/")
	mount := strings.Split(strings.Trim(b.cfg.EffectiveMount(), "/"), "/")
	if b.cfg.EffectiveKVVersion() == 1 {
		if version != "" {
			return "", fmt.Errorf("%w: KV version 1 has no versions", secretstore.ErrInvalidPayload)
		}
		return b.endpoint(append(mount, segments...)...), nil
	}
	target := b.endpoint(append(append(mount, "data"), segments...)...)
	if version != "" {
		n, err := strconv.Atoi(version)
		if err != nil || n <= 0 {
			return "", fmt.Errorf("%w: a KV version is a positive integer", secretstore.ErrInvalidPayload)
		}
		target += "?" + url.Values{"version": {strconv.Itoa(n)}}.Encode()
	}
	return target, nil
}

// endpoint joins escaped segments under /v1 of the store's address.
func (b *Backend) endpoint(segments ...string) string {
	escaped := make([]string, len(segments))
	for i, s := range segments {
		escaped[i] = url.PathEscape(s)
	}
	return b.base.String() + "/v1/" + strings.Join(escaped, "/")
}

func (b *Backend) decode(raw []byte) (secretstore.Secret, error) {
	if b.cfg.EffectiveKVVersion() == 1 {
		var body struct {
			Data map[string]any `json:"data"`
		}
		if err := json.Unmarshal(raw, &body); err != nil || body.Data == nil {
			return secretstore.Secret{}, fmt.Errorf("%w: unexpected KV response", secretstore.ErrInvalidPayload)
		}
		return secretstore.NewKVSecret(body.Data, ""), nil
	}
	var body struct {
		Data struct {
			Data     map[string]any `json:"data"`
			Metadata struct {
				Version int `json:"version"`
			} `json:"metadata"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		return secretstore.Secret{}, fmt.Errorf("%w: unexpected KV response", secretstore.ErrInvalidPayload)
	}
	if body.Data.Data == nil {
		return secretstore.Secret{}, fmt.Errorf("%w: the version is deleted or destroyed", secretstore.ErrNotFound)
	}
	version := ""
	if body.Data.Metadata.Version > 0 {
		version = strconv.Itoa(body.Data.Metadata.Version)
	}
	return secretstore.NewKVSecret(body.Data.Data, version), nil
}

func (b *Backend) do(ctx context.Context, method, target, token string, body any) (*http.Response, error) {
	var payload *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("%w: encoding the request", secretstore.ErrUnavailable)
		}
		payload = bytes.NewReader(raw)
	} else {
		payload = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return nil, fmt.Errorf("%w: building the request", secretstore.ErrInvalidPayload)
	}
	if token != "" {
		req.Header.Set("X-Vault-Token", token)
	}
	if b.cfg.Namespace != "" {
		req.Header.Set("X-Vault-Namespace", b.cfg.Namespace)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := b.client.Do(req)
	if err != nil {
		return nil, httpclient.TransportError(err)
	}
	return resp, nil
}
