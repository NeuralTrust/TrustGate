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

package hashicorp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	"github.com/NeuralTrust/TrustGate/pkg/infra/secretstore/internal/httpclient"
)

type authResponse struct {
	Auth *struct {
		ClientToken   string `json:"client_token"`
		LeaseDuration int    `json:"lease_duration"`
		Renewable     bool   `json:"renewable"`
	} `json:"auth"`
}

// ensureToken returns a usable token, renewing or logging in when the
// current one is missing or past two thirds of its lease. One login or
// renewal runs at a time.
func (b *Backend) ensureToken(ctx context.Context) (string, error) {
	if token, ok := b.currentToken(); ok {
		return token, nil
	}
	b.loginMu.Lock()
	defer b.loginMu.Unlock()
	if token, ok := b.currentToken(); ok {
		return token, nil
	}
	b.mu.Lock()
	token, renewable, expired := b.token, b.renewable, b.expired()
	b.mu.Unlock()
	if token != "" && renewable && !expired {
		if err := b.renew(ctx, token); err == nil {
			b.mu.Lock()
			defer b.mu.Unlock()
			return b.token, nil
		}
	}
	return b.loginLocked(ctx)
}

func (b *Backend) currentToken() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.token == "" {
		return "", false
	}
	if b.lease <= 0 {
		return b.token, true
	}
	renewAt := b.issuedAt.Add(b.lease * 2 / 3)
	return b.token, b.now().Before(renewAt)
}

func (b *Backend) expired() bool {
	return b.lease > 0 && !b.now().Before(b.issuedAt.Add(b.lease))
}

// reloginAfterDenied logs in again after a read with used was denied, at most
// once per reloginGap, and returns the token to retry with. An empty token
// and no error means no login was due, so the denial stands; a login that
// was attempted and failed returns its own error, so a store that cannot be
// reached is not mistaken for a revoked secret.
func (b *Backend) reloginAfterDenied(ctx context.Context, used string) (string, error) {
	b.loginMu.Lock()
	defer b.loginMu.Unlock()
	b.mu.Lock()
	current, last := b.token, b.lastLogin
	b.mu.Unlock()
	if current != "" && current != used {
		return current, nil
	}
	if !last.IsZero() && b.now().Sub(last) < reloginGap {
		return "", nil
	}
	return b.loginLocked(ctx)
}

func (b *Backend) dropToken(used string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.token == used {
		b.token = ""
	}
}

// loginLocked logs in with the configured method. The caller holds loginMu.
func (b *Backend) loginLocked(ctx context.Context) (string, error) {
	auth := b.cfg.Auth
	now := b.now()
	if auth.Method == secretstore.VaultAuthToken {
		token, err := b.credential(auth.TokenFile)
		if err != nil {
			return "", err
		}
		b.store(token, false, 0, now)
		return token, nil
	}

	var body map[string]string
	switch auth.Method {
	case secretstore.VaultAuthKubernetes, secretstore.VaultAuthJWT:
		jwt, err := b.credential(auth.EffectiveJWTFile())
		if err != nil {
			return "", err
		}
		body = map[string]string{"role": auth.Role, "jwt": jwt}
	case secretstore.VaultAuthAppRole:
		secretID, err := b.credential(auth.SecretIDFile)
		if err != nil {
			return "", err
		}
		body = map[string]string{"role_id": auth.RoleID, "secret_id": secretID}
	default:
		return "", fmt.Errorf("%w: unknown auth method", secretstore.ErrAuthFailed)
	}

	mount := strings.Split(strings.Trim(auth.EffectiveMount(), "/"), "/")
	target := b.endpoint(append(append([]string{"auth"}, mount...), "login")...)
	resp, err := b.do(ctx, http.MethodPost, target, "", body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		httpclient.Discard(resp)
		if resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500 {
			return "", httpclient.StatusError(resp.StatusCode)
		}
		return "", fmt.Errorf("%w: login answered %d", secretstore.ErrAuthFailed, resp.StatusCode)
	}
	raw, err := httpclient.ReadBody(resp)
	if err != nil {
		return "", err
	}
	var parsed authResponse
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Auth == nil || parsed.Auth.ClientToken == "" {
		return "", fmt.Errorf("%w: login returned no token", secretstore.ErrAuthFailed)
	}
	lease := time.Duration(parsed.Auth.LeaseDuration) * time.Second
	b.store(parsed.Auth.ClientToken, parsed.Auth.Renewable, lease, now)
	return parsed.Auth.ClientToken, nil
}

func (b *Backend) renew(ctx context.Context, token string) error {
	resp, err := b.do(ctx, http.MethodPost, b.endpoint("auth", "token", "renew-self"), token, map[string]string{})
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		httpclient.Discard(resp)
		return fmt.Errorf("%w: renewal answered %d", secretstore.ErrAuthFailed, resp.StatusCode)
	}
	raw, err := httpclient.ReadBody(resp)
	if err != nil {
		return err
	}
	var parsed authResponse
	if err := json.Unmarshal(raw, &parsed); err != nil || parsed.Auth == nil {
		return fmt.Errorf("%w: renewal returned no lease", secretstore.ErrAuthFailed)
	}
	renewed := parsed.Auth.ClientToken
	if renewed == "" {
		renewed = token
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.token = renewed
	b.renewable = parsed.Auth.Renewable
	b.lease = time.Duration(parsed.Auth.LeaseDuration) * time.Second
	b.issuedAt = b.now()
	return nil
}

func (b *Backend) store(token string, renewable bool, lease time.Duration, now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.token, b.renewable, b.lease, b.issuedAt, b.lastLogin = token, renewable, lease, now, now
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
