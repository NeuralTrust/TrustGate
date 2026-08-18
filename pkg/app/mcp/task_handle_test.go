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
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

const testHandleFingerprint = "fingerprint-1"

func testHandleClaims() TaskHandleClaims {
	return TaskHandleClaims{
		GID:      "gateway-1",
		CID:      "consumer-1",
		RID:      "registry-1",
		Sub:      testHandleFingerprint,
		Exposed:  "find",
		Upstream: "search",
		TaskID:   "u-123",
	}
}

func fixedTaskSigner(secret, prev string, ttl time.Duration, now time.Time) *TaskHandleSigner {
	return NewTaskHandleSigner(secret, prev, ttl, 0).WithClock(func() time.Time { return now })
}

func TestTaskHandleSigner_Enabled(t *testing.T) {
	t.Parallel()
	if NewTaskHandleSigner("", "", 0, 0).Enabled() {
		t.Fatal("an empty secret must disable the signer")
	}
	if !NewTaskHandleSigner("secret", "", 0, 0).Enabled() {
		t.Fatal("a configured secret must enable the signer")
	}
	if _, err := NewTaskHandleSigner("", "", 0, 0).Mint(testHandleClaims()); !errors.Is(err, ErrTaskHandleRejected) {
		t.Fatalf("mint err = %v, want ErrTaskHandleRejected", err)
	}
}

func TestTaskHandleSigner_MintUnwrapBinds(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	signer := fixedTaskSigner("secret", "", time.Hour, now)
	handle, err := signer.Mint(testHandleClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if !strings.HasPrefix(handle, taskHandleVersion+"."+envelopeKidCurrent+".") {
		t.Fatalf("handle = %q", handle)
	}
	claims, err := signer.Unwrap(handle)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if claims.TaskID != "u-123" || claims.V != taskHandleClaimVersion {
		t.Fatalf("claims = %+v", claims)
	}
	if !claims.Binds("gateway-1", "consumer-1", "registry-1", testHandleFingerprint, "find", "search") {
		t.Fatal("the minted claims must bind the request they were minted for")
	}
}

func TestTaskHandleClaims_BindsRejectsEveryFieldMismatch(t *testing.T) {
	t.Parallel()
	claims := testHandleClaims()
	cases := []struct {
		name                                                   string
		gateway, consumer, registry, principal, exposed, upstr string
	}{
		{"gateway", "other", "consumer-1", "registry-1", testHandleFingerprint, "find", "search"},
		{"consumer", "gateway-1", "other", "registry-1", testHandleFingerprint, "find", "search"},
		{"registry", "gateway-1", "consumer-1", "other", testHandleFingerprint, "find", "search"},
		{"principal", "gateway-1", "consumer-1", "registry-1", "other", "find", "search"},
		{"exposed", "gateway-1", "consumer-1", "registry-1", testHandleFingerprint, "other", "search"},
		{"upstream", "gateway-1", "consumer-1", "registry-1", testHandleFingerprint, "find", "other"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if claims.Binds(tc.gateway, tc.consumer, tc.registry, tc.principal, tc.exposed, tc.upstr) {
				t.Fatalf("a %s mismatch must not bind", tc.name)
			}
		})
	}
}

func TestTaskHandleSigner_ExpiryIsTheEarlierOfTTLAndUpstreamDeadline(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)

	upstreamSooner := now.Add(10 * time.Minute).Unix()
	claims := testHandleClaims()
	claims.Exp = upstreamSooner
	handle, err := fixedTaskSigner("secret", "", time.Hour, now).Mint(claims)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := fixedTaskSigner("secret", "", time.Hour, now).Unwrap(handle)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if got.Exp != upstreamSooner {
		t.Fatalf("exp = %d, want the upstream deadline %d", got.Exp, upstreamSooner)
	}

	upstreamLater := now.Add(10 * time.Hour).Unix()
	claims.Exp = upstreamLater
	handle, err = fixedTaskSigner("secret", "", time.Hour, now).Mint(claims)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err = fixedTaskSigner("secret", "", time.Hour, now).Unwrap(handle)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if want := now.Add(time.Hour).Unix(); got.Exp != want {
		t.Fatalf("exp = %d, want the configured TTL %d", got.Exp, want)
	}
}

func TestTaskHandleSigner_TTLClampedToCeiling(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	signer := fixedTaskSigner("secret", "", 72*time.Hour, now)
	handle, err := signer.Mint(testHandleClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	claims, err := signer.Unwrap(handle)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if want := now.Add(MaxTaskHandleTTL).Unix(); claims.Exp != want {
		t.Fatalf("exp = %d, want the 24h ceiling %d", claims.Exp, want)
	}
}

func TestTaskHandleSigner_Expired(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	signer := NewTaskHandleSigner("secret", "", time.Hour, 0).WithClock(func() time.Time { return now })
	handle, err := signer.Mint(testHandleClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	signer.WithClock(func() time.Time { return now.Add(time.Hour + time.Second) })
	if _, err := signer.Unwrap(handle); !errors.Is(err, ErrTaskHandleRejected) {
		t.Fatalf("err = %v, want ErrTaskHandleRejected", err)
	}
}

func TestTaskHandleSigner_OversizeFailsClosed(t *testing.T) {
	t.Parallel()
	claims := testHandleClaims()
	claims.Exposed = strings.Repeat("x", 4096)
	if _, err := NewTaskHandleSigner("secret", "", time.Hour, 0).Mint(claims); !errors.Is(err, ErrTaskHandleTooLarge) {
		t.Fatalf("err = %v, want ErrTaskHandleTooLarge", err)
	}
}

func TestTaskHandleSigner_Rotation(t *testing.T) {
	t.Parallel()
	handle, err := NewTaskHandleSigner("old", "", time.Hour, 0).Mint(testHandleClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := NewTaskHandleSigner("new", "old", time.Hour, 0).Unwrap(handle); err != nil {
		t.Fatalf("a handle minted under the previous secret must still verify: %v", err)
	}
	if _, err := NewTaskHandleSigner("new", "other", time.Hour, 0).Unwrap(handle); !errors.Is(err, ErrTaskHandleRejected) {
		t.Fatalf("err = %v, want ErrTaskHandleRejected", err)
	}
}

// An MRTR ticket and a task handle share the same crypto but never the same
// namespace: the version prefix and the purpose tag both separate them.
func TestTaskHandleSigner_CrossPrimitiveRejection(t *testing.T) {
	t.Parallel()
	ticket, err := NewTicketSigner("secret", "", time.Minute, 8).Mint(testClaims())
	if err != nil {
		t.Fatalf("mint ticket: %v", err)
	}
	if _, err := NewTaskHandleSigner("secret", "", time.Hour, 0).Unwrap(ticket); !errors.Is(err, ErrTaskHandleRejected) {
		t.Fatalf("an MRTR ticket must not unwrap as a handle: %v", err)
	}
	handle, err := NewTaskHandleSigner("secret", "", time.Hour, 0).Mint(testHandleClaims())
	if err != nil {
		t.Fatalf("mint handle: %v", err)
	}
	if _, err := NewTicketSigner("secret", "", time.Minute, 8).Unwrap(handle); !errors.Is(err, ErrMRTRReplayRejected) {
		t.Fatalf("a handle must not unwrap as an MRTR ticket: %v", err)
	}
}

func TestTaskHandleSigner_UnwrapRejectsTamperedClaims(t *testing.T) {
	t.Parallel()
	signer := NewTaskHandleSigner("secret", "", time.Hour, 0)
	handle, err := signer.Mint(testHandleClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parts := strings.Split(handle, ".")
	parts[2] = strings.Repeat("A", len(parts[2]))
	if _, err := signer.Unwrap(strings.Join(parts, ".")); !errors.Is(err, ErrTaskHandleRejected) {
		t.Fatalf("err = %v, want ErrTaskHandleRejected", err)
	}
}

func TestPrincipalFingerprint(t *testing.T) {
	t.Parallel()
	if got := principalFingerprint(context.Background()); got != "" {
		t.Fatalf("fingerprint without a principal = %q, want empty", got)
	}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Issuer: "iss", Subject: "sub"})
	got := principalFingerprint(ctx)
	if len(got) != 64 {
		t.Fatalf("fingerprint = %q, want the full sha256 hex digest", got)
	}
	// The discovery cache key must keep the exact bytes it used before the
	// fingerprint was shared with the handle signer.
	if len(got[:discoveryFingerprintHexLen]) != 16 {
		t.Fatalf("truncated fingerprint = %q", got[:discoveryFingerprintHexLen])
	}
	other := identity.WithPrincipal(context.Background(), &identity.Principal{Issuer: "iss", Subject: "other"})
	if principalFingerprint(other) == got {
		t.Fatal("a different subject must produce a different fingerprint")
	}
}
