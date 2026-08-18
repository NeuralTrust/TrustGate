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

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

const (
	taskHandleVersion      = "tg1k"
	taskHandlePurpose      = "mcp.task.handle.v1"
	taskHandleClaimVersion = 1

	// DefaultTaskHandleTTL is how long a task handle stays usable when the
	// operator configured no explicit TTL.
	DefaultTaskHandleTTL = time.Hour
	// MaxTaskHandleTTL is the ceiling every configured TTL is clamped to.
	MaxTaskHandleTTL = 24 * time.Hour
	// DefaultTaskHandleMaxBytes bounds the handle a client has to echo back.
	DefaultTaskHandleMaxBytes = 1024
)

// TaskHandleClaims binds a mediated upstream task to the exact caller, surface,
// and registry it was created for.
type TaskHandleClaims struct {
	V        int    `json:"v"`
	GID      string `json:"gid"`
	CID      string `json:"cid"`
	RID      string `json:"rid"`
	Sub      string `json:"sub"`
	Exposed  string `json:"expn"`
	Upstream string `json:"upn"`
	TaskID   string `json:"tid"`
	Created  int64  `json:"iat"`
	Exp      int64  `json:"exp"`
}

// Binds reports whether the claims match the request being served. Every field
// must match; a mismatch is indistinguishable from a forged handle.
func (c TaskHandleClaims) Binds(gatewayID, consumerID, registryID, principal, exposed, upstream string) bool {
	return c.GID == gatewayID &&
		c.CID == consumerID &&
		c.RID == registryID &&
		c.Sub == principal &&
		c.Exposed == exposed &&
		c.Upstream == upstream
}

// TaskHandleSigner mints and verifies stateless task handles. It carries its own
// secret, so unsetting that secret disables task mediation without touching MRTR.
type TaskHandleSigner struct {
	env *signedEnvelope
}

// NewTaskHandleSigner builds a signer, clamping the TTL to MaxTaskHandleTTL and
// falling back to the default handle size bound when it is not positive.
func NewTaskHandleSigner(secret, prev string, ttl time.Duration, maxBytes int) *TaskHandleSigner {
	if ttl <= 0 {
		ttl = DefaultTaskHandleTTL
	}
	if ttl > MaxTaskHandleTTL {
		ttl = MaxTaskHandleTTL
	}
	if maxBytes <= 0 {
		maxBytes = DefaultTaskHandleMaxBytes
	}
	return &TaskHandleSigner{
		env: newSignedEnvelope(taskHandleVersion, taskHandlePurpose, secret, prev, ttl, maxBytes),
	}
}

// WithClock replaces the clock used for expiry, for tests.
func (s *TaskHandleSigner) WithClock(now func() time.Time) *TaskHandleSigner {
	if s == nil {
		return s
	}
	s.env.withClock(now)
	return s
}

// Enabled reports whether a current secret is configured.
func (s *TaskHandleSigner) Enabled() bool {
	return s != nil && s.env.enabled()
}

// Mint signs the claims, resolving the expiry to the earlier of the configured
// TTL and any deadline the upstream declared.
func (s *TaskHandleSigner) Mint(claims TaskHandleClaims) (string, error) {
	if !s.Enabled() {
		return "", ErrTaskHandleRejected
	}
	claims.V = taskHandleClaimVersion
	claims.Exp = s.env.expiry(claims.Exp)
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", ErrTaskHandleTooLarge
	}
	handle, err := s.env.seal(payload)
	if err != nil {
		if errors.Is(err, errEnvelopeTooLarge) {
			return "", ErrTaskHandleTooLarge
		}
		return "", ErrTaskHandleRejected
	}
	return handle, nil
}

// Unwrap verifies a handle and returns its claims. Every failure is reported as
// ErrTaskHandleRejected so a handle cannot be used as an existence oracle.
func (s *TaskHandleSigner) Unwrap(handle string) (*TaskHandleClaims, error) {
	if !s.Enabled() {
		return nil, ErrTaskHandleRejected
	}
	payload, err := s.env.open(handle)
	if err != nil {
		return nil, ErrTaskHandleRejected
	}
	var claims TaskHandleClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrTaskHandleRejected
	}
	if claims.V != taskHandleClaimVersion || claims.TaskID == "" {
		return nil, ErrTaskHandleRejected
	}
	if s.env.expired(claims.Exp) {
		return nil, ErrTaskHandleRejected
	}
	return &claims, nil
}

// principalFingerprint is the stable digest of the acting principal, or "" when
// the request carries none. It is the full digest: discoveryKey truncates it for
// its own cache keys, the task handle binds all of it.
func principalFingerprint(ctx context.Context) string {
	p := identity.PrincipalFromContext(ctx)
	if p == nil {
		return ""
	}
	sum := sha256.Sum256([]byte(p.Issuer + "|" + p.Subject))
	return hex.EncodeToString(sum[:])
}
