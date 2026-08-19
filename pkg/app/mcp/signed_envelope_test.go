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
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func testEnvelope(secret, prev string) *signedEnvelope {
	return newSignedEnvelope("tgx", "test.purpose.v1", secret, prev, time.Minute, 0)
}

func TestSignedEnvelope_Disabled(t *testing.T) {
	t.Parallel()
	env := testEnvelope("", "")
	if env.enabled() {
		t.Fatal("an empty secret must leave the envelope disabled")
	}
	if _, err := env.seal([]byte(`{"a":1}`)); !errors.Is(err, errEnvelopeDisabled) {
		t.Fatalf("seal err = %v, want errEnvelopeDisabled", err)
	}
	if _, err := env.open("tgx.c.x.y"); !errors.Is(err, errEnvelopeRejected) {
		t.Fatalf("open err = %v, want errEnvelopeRejected", err)
	}
}

func TestSignedEnvelope_RoundTrip(t *testing.T) {
	t.Parallel()
	env := testEnvelope("secret", "")
	token, err := env.seal([]byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 4 || parts[0] != "tgx" || parts[1] != envelopeKidCurrent {
		t.Fatalf("token = %q", token)
	}
	payload, err := env.open(token)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(payload) != `{"a":1}` {
		t.Fatalf("payload = %s", payload)
	}
}

func TestSignedEnvelope_Rejections(t *testing.T) {
	t.Parallel()
	env := testEnvelope("secret", "")
	token, err := env.seal([]byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	mutate := func(index int, value string) string {
		parts := strings.Split(token, ".")
		parts[index] = value
		return strings.Join(parts, ".")
	}
	cases := []struct {
		name  string
		token string
	}{
		{"tampered mac", mutate(3, base64.RawURLEncoding.EncodeToString([]byte("nope")))},
		{"tampered payload", mutate(2, base64.RawURLEncoding.EncodeToString([]byte(`{"a":2}`)))},
		{"unknown version", mutate(0, "tgz")},
		{"unknown kid", mutate(1, "x")},
		{"not base64", mutate(2, "!!!")},
		{"too few parts", "tgx.c.abc"},
		{"empty", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := env.open(tc.token); !errors.Is(err, errEnvelopeRejected) {
				t.Fatalf("open(%q) err = %v", tc.token, err)
			}
		})
	}
}

func TestSignedEnvelope_Rotation(t *testing.T) {
	t.Parallel()
	token, err := testEnvelope("old", "").seal([]byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	if _, err := testEnvelope("new", "old").open(token); err != nil {
		t.Fatalf("a token minted under the previous secret must still open: %v", err)
	}
	if _, err := testEnvelope("new", "other").open(token); !errors.Is(err, errEnvelopeRejected) {
		t.Fatalf("err = %v, want errEnvelopeRejected", err)
	}
}

func TestSignedEnvelope_PurposeSeparation(t *testing.T) {
	t.Parallel()
	tagged := newSignedEnvelope("tgx", "purpose.a", "secret", "", time.Minute, 0)
	other := newSignedEnvelope("tgx", "purpose.b", "secret", "", time.Minute, 0)
	untagged := newSignedEnvelope("tgx", "", "secret", "", time.Minute, 0)

	taggedToken, err := tagged.seal([]byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("seal tagged: %v", err)
	}
	untaggedToken, err := untagged.seal([]byte(`{"a":1}`))
	if err != nil {
		t.Fatalf("seal untagged: %v", err)
	}
	if taggedToken == untaggedToken {
		t.Fatal("the purpose tag must change the MAC")
	}
	if _, err := other.open(taggedToken); !errors.Is(err, errEnvelopeRejected) {
		t.Fatalf("a different purpose must not verify: %v", err)
	}
	if _, err := untagged.open(taggedToken); !errors.Is(err, errEnvelopeRejected) {
		t.Fatalf("an untagged envelope must not verify a tagged token: %v", err)
	}
	if _, err := tagged.open(untaggedToken); !errors.Is(err, errEnvelopeRejected) {
		t.Fatalf("a tagged envelope must not verify an untagged token: %v", err)
	}
}

func TestSignedEnvelope_UntaggedMACInputMatchesLegacyForm(t *testing.T) {
	t.Parallel()
	env := newSignedEnvelope("tg1", "", "secret", "", time.Minute, 0)
	if got := env.macInput("", "c", "payload"); got != "tg1.c.payload" {
		t.Fatalf("untagged MAC input = %q", got)
	}
	if got := env.macInput("p1", "c", "payload"); got != "p1|tg1.c.payload" {
		t.Fatalf("tagged MAC input = %q", got)
	}
}

func TestSignedEnvelope_SizeBound(t *testing.T) {
	t.Parallel()
	env := newSignedEnvelope("tgx", "purpose", "secret", "", time.Minute, 32)
	if _, err := env.seal([]byte(strings.Repeat("a", 128))); !errors.Is(err, errEnvelopeTooLarge) {
		t.Fatalf("seal err = %v, want errEnvelopeTooLarge", err)
	}
	unbounded := newSignedEnvelope("tgx", "purpose", "secret", "", time.Minute, 0)
	token, err := unbounded.seal([]byte(strings.Repeat("a", 128)))
	if err != nil {
		t.Fatalf("seal unbounded: %v", err)
	}
	if _, err := env.open(token); !errors.Is(err, errEnvelopeRejected) {
		t.Fatalf("an oversize token must be rejected before decoding: %v", err)
	}
}

func TestSignedEnvelope_Expiry(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	env := newSignedEnvelope("tgx", "purpose", "secret", "", time.Hour, 0)
	env.withClock(func() time.Time { return now })

	if got, want := env.expiry(0), now.Add(time.Hour).Unix(); got != want {
		t.Fatalf("expiry(0) = %d, want %d", got, want)
	}
	earlier := now.Add(time.Minute).Unix()
	if got := env.expiry(earlier); got != earlier {
		t.Fatalf("expiry(earlier) = %d, want %d", got, earlier)
	}
	later := now.Add(10 * time.Hour).Unix()
	if got, want := env.expiry(later), now.Add(time.Hour).Unix(); got != want {
		t.Fatalf("expiry(later) = %d, want %d", got, want)
	}
	if env.expired(now.Add(time.Second).Unix()) {
		t.Fatal("a future expiry must not be expired")
	}
	if !env.expired(now.Unix()) {
		t.Fatal("an expiry equal to now must be expired")
	}
}
