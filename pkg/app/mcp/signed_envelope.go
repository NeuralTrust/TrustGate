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
	"errors"
	"strings"
	"time"
)

const (
	envelopeKidCurrent  = "c"
	envelopeKidPrevious = "p"
)

var (
	errEnvelopeDisabled = errors.New("mcp: signed envelope disabled")
	errEnvelopeRejected = errors.New("mcp: signed envelope rejected")
	errEnvelopeTooLarge = errors.New("mcp: signed envelope too large")
)

// signedEnvelope is the shared HMAC framing behind MRTR tickets and task
// handles: <version>.<kid>.<b64url(payload)>.<b64url(hmac)>. An empty purpose
// keeps the MAC input untagged, which is the form MRTR has always signed.
type signedEnvelope struct {
	version  string
	purpose  string
	current  []byte
	previous []byte
	ttl      time.Duration
	maxBytes int
	now      func() time.Time
}

func newSignedEnvelope(version, purpose, secret, prev string, ttl time.Duration, maxBytes int) *signedEnvelope {
	return &signedEnvelope{
		version:  version,
		purpose:  purpose,
		current:  []byte(secret),
		previous: []byte(prev),
		ttl:      ttl,
		maxBytes: maxBytes,
		now:      time.Now,
	}
}

func (e *signedEnvelope) enabled() bool {
	return e != nil && len(e.current) > 0
}

func (e *signedEnvelope) withClock(now func() time.Time) {
	if e == nil || now == nil {
		return
	}
	e.now = now
}

// expiry resolves the effective expiry: the configured TTL, lowered to an
// explicit deadline whenever the caller supplied one.
func (e *signedEnvelope) expiry(explicit int64) int64 {
	ttlExpiry := e.now().Add(e.ttl).Unix()
	if explicit > 0 && explicit < ttlExpiry {
		return explicit
	}
	return ttlExpiry
}

func (e *signedEnvelope) expired(exp int64) bool {
	return exp <= e.now().Unix()
}

func (e *signedEnvelope) seal(payload []byte) (string, error) {
	if !e.enabled() {
		return "", errEnvelopeDisabled
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	macInput := e.macInput(e.purpose, envelopeKidCurrent, encoded)
	sum := hmacSHA256(e.current, macInput)
	token := e.version + "." + envelopeKidCurrent + "." + encoded + "." +
		base64.RawURLEncoding.EncodeToString(sum)
	if e.maxBytes > 0 && len(token) > e.maxBytes {
		return "", errEnvelopeTooLarge
	}
	return token, nil
}

func (e *signedEnvelope) open(token string) ([]byte, error) {
	if !e.enabled() {
		return nil, errEnvelopeRejected
	}
	if e.maxBytes > 0 && len(token) > e.maxBytes {
		return nil, errEnvelopeRejected
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != e.version {
		return nil, errEnvelopeRejected
	}
	kid := parts[1]
	if kid != envelopeKidCurrent && kid != envelopeKidPrevious {
		return nil, errEnvelopeRejected
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, errEnvelopeRejected
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, errEnvelopeRejected
	}
	if !e.verify(e.macInput(e.purpose, kid, parts[2]), sig) {
		return nil, errEnvelopeRejected
	}
	return payload, nil
}

func (e *signedEnvelope) verify(macInput string, sig []byte) bool {
	if hmac.Equal(sig, hmacSHA256(e.current, macInput)) {
		return true
	}
	return len(e.previous) > 0 && hmac.Equal(sig, hmacSHA256(e.previous, macInput))
}

// macInput keeps the untagged form byte-identical to the MRTR MAC that shipped
// before the envelope was extracted, so live tickets survive the refactor.
func (e *signedEnvelope) macInput(purpose, kid, payload string) string {
	if purpose == "" {
		return e.version + "." + kid + "." + payload
	}
	return purpose + "|" + e.version + "." + kid + "." + payload
}

func hmacSHA256(key []byte, macInput string) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(macInput))
	return mac.Sum(nil)
}
