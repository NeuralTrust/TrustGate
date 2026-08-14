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
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"time"
)

const (
	ticketVersion        = "tg1"
	ticketKidCurrent     = "c"
	ticketKidPrevious    = "p"
	ticketClaimVersion   = 1
	defaultTicketTTL     = 5 * time.Minute
	DefaultMRTRMaxRounds = 8
	MethodToolsCall      = "tools/call"
)

// TicketClaims is the continuation binding a ticket carries: the consumer,
// registry, exposed and upstream tool, method, round, expiry, and the upstream's
// own opaque state.
type TicketClaims struct {
	V        int    `json:"v"`
	CID      string `json:"cid"`
	RID      string `json:"rid"`
	Exposed  string `json:"expn"`
	Upstream string `json:"upn"`
	Method   string `json:"m"`
	Round    int    `json:"r"`
	Exp      int64  `json:"exp"`
	State    string `json:"st"`
}

// Binds reports whether the claims match the request being served.
func (c TicketClaims) Binds(consumerID, registryID, exposed, upstream, method string) bool {
	return c.CID == consumerID &&
		c.RID == registryID &&
		c.Exposed == exposed &&
		c.Upstream == upstream &&
		c.Method == method
}

// TicketSigner mints and verifies stateless HMAC continuation tickets. A signer
// with no current secret is disabled and rejects every ticket.
type TicketSigner struct {
	current   []byte
	previous  []byte
	ttl       time.Duration
	maxRounds int
	now       func() time.Time
}

// NewTicketSigner builds a signer from the current and previous secrets, falling
// back to the default TTL and round cap when either is unset.
func NewTicketSigner(secret, prev string, ttl time.Duration, maxRounds int) *TicketSigner {
	if ttl <= 0 {
		ttl = defaultTicketTTL
	}
	if maxRounds <= 0 {
		maxRounds = DefaultMRTRMaxRounds
	}
	return &TicketSigner{
		current:   []byte(secret),
		previous:  []byte(prev),
		ttl:       ttl,
		maxRounds: maxRounds,
		now:       time.Now,
	}
}

// WithClock replaces the clock used for expiry, for tests.
func (s *TicketSigner) WithClock(now func() time.Time) *TicketSigner {
	if s == nil {
		return s
	}
	s.now = now
	return s
}

// Enabled reports whether a current secret is configured.
func (s *TicketSigner) Enabled() bool {
	return s != nil && len(s.current) > 0
}

// MaxRounds is the highest round a continuation may reach.
func (s *TicketSigner) MaxRounds() int {
	if s == nil || s.maxRounds <= 0 {
		return DefaultMRTRMaxRounds
	}
	return s.maxRounds
}

// Mint signs the claims with the current secret and stamps the expiry when the
// caller left it unset.
func (s *TicketSigner) Mint(claims TicketClaims) (string, error) {
	if !s.Enabled() {
		return "", ErrMRTRReplayRejected
	}
	claims.V = ticketClaimVersion
	if claims.Exp == 0 {
		claims.Exp = s.now().Add(s.ttl).Unix()
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	macInput := ticketVersion + "." + ticketKidCurrent + "." + encoded
	sum := hmacSHA256(s.current, macInput)
	return macInput + "." + base64.RawURLEncoding.EncodeToString(sum), nil
}

// Unwrap verifies a ticket against the current secret, then the previous one, and
// returns its claims. Every failure is reported as ErrMRTRReplayRejected so a
// client cannot tell a forged ticket from an expired one.
func (s *TicketSigner) Unwrap(ticket string) (*TicketClaims, error) {
	if !s.Enabled() {
		return nil, ErrMRTRReplayRejected
	}
	parts := strings.Split(ticket, ".")
	if len(parts) != 4 || parts[0] != ticketVersion {
		return nil, ErrMRTRReplayRejected
	}
	kid := parts[1]
	if kid != ticketKidCurrent && kid != ticketKidPrevious {
		return nil, ErrMRTRReplayRejected
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMRTRReplayRejected
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, ErrMRTRReplayRejected
	}
	macInput := parts[0] + "." + parts[1] + "." + parts[2]
	if !s.verifyMAC(macInput, sig) {
		return nil, ErrMRTRReplayRejected
	}
	var claims TicketClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, ErrMRTRReplayRejected
	}
	if claims.V != ticketClaimVersion {
		return nil, ErrMRTRReplayRejected
	}
	if claims.Exp <= s.now().Unix() {
		return nil, ErrMRTRReplayRejected
	}
	return &claims, nil
}

func (s *TicketSigner) verifyMAC(macInput string, sig []byte) bool {
	if hmac.Equal(sig, hmacSHA256(s.current, macInput)) {
		return true
	}
	if len(s.previous) > 0 && hmac.Equal(sig, hmacSHA256(s.previous, macInput)) {
		return true
	}
	return false
}

func hmacSHA256(key []byte, macInput string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(macInput))
	return mac.Sum(nil)
}
