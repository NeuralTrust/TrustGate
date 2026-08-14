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
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func testClaims() TicketClaims {
	return TicketClaims{
		CID:      "consumer-1",
		RID:      "registry-1",
		Exposed:  "search",
		Upstream: "search",
		Method:   MethodToolsCall,
		Round:    1,
	}
}

func TestTicketSigner_Enabled(t *testing.T) {
	t.Parallel()
	if NewTicketSigner("", "", 0, 0).Enabled() {
		t.Fatal("empty secret must disable the signer")
	}
	if !NewTicketSigner("secret", "", 0, 0).Enabled() {
		t.Fatal("non-empty secret must enable the signer")
	}
}

func TestTicketSigner_MintEmptyState(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	signer := NewTicketSigner("secret", "", time.Minute, 8).WithClock(func() time.Time { return now })
	ticket, err := signer.Mint(testClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parts := strings.Split(ticket, ".")
	if len(parts) != 4 || parts[0] != ticketVersion || parts[1] != ticketKidCurrent {
		t.Fatalf("ticket = %q", ticket)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("payload: %v", err)
	}
	var claims TicketClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("claims: %v", err)
	}
	if claims.State != "" || claims.V != 1 || claims.Exp != now.Add(time.Minute).Unix() {
		t.Fatalf("claims = %+v", claims)
	}
	got, err := signer.Unwrap(ticket)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if got.State != "" || !got.Binds("consumer-1", "registry-1", "search", "search", MethodToolsCall) {
		t.Fatalf("unwrapped = %+v", got)
	}
}

func TestTicketSigner_HMACMismatch(t *testing.T) {
	t.Parallel()
	signer := NewTicketSigner("secret", "", time.Minute, 8)
	ticket, err := signer.Mint(testClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parts := strings.Split(ticket, ".")
	parts[3] = base64.RawURLEncoding.EncodeToString([]byte("tampered-signature-bytes"))
	if _, err := signer.Unwrap(strings.Join(parts, ".")); !errors.Is(err, ErrMRTRReplayRejected) {
		t.Fatalf("err = %v", err)
	}
}

func TestTicketSigner_Expired(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	signer := NewTicketSigner("secret", "", time.Minute, 8).WithClock(func() time.Time { return now })
	ticket, err := signer.Mint(testClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	signer.WithClock(func() time.Time { return now.Add(2 * time.Minute) })
	if _, err := signer.Unwrap(ticket); !errors.Is(err, ErrMRTRReplayRejected) {
		t.Fatalf("err = %v", err)
	}
}

func TestTicketSigner_PreviousKid(t *testing.T) {
	t.Parallel()
	old := NewTicketSigner("old-secret", "", time.Minute, 8)
	ticket, err := old.Mint(testClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	rotated := NewTicketSigner("new-secret", "old-secret", time.Minute, 8)
	got, err := rotated.Unwrap(ticket)
	if err != nil {
		t.Fatalf("unwrap after rotation: %v", err)
	}
	if got.CID != "consumer-1" {
		t.Fatalf("claims = %+v", got)
	}
	if _, err := NewTicketSigner("new-secret", "other", time.Minute, 8).Unwrap(ticket); !errors.Is(err, ErrMRTRReplayRejected) {
		t.Fatalf("err = %v", err)
	}
}

func TestTicketSigner_UnknownKid(t *testing.T) {
	t.Parallel()
	signer := NewTicketSigner("secret", "", time.Minute, 8)
	ticket, err := signer.Mint(testClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	parts := strings.Split(ticket, ".")
	parts[1] = "x"
	if _, err := signer.Unwrap(strings.Join(parts, ".")); !errors.Is(err, ErrMRTRReplayRejected) {
		t.Fatalf("err = %v", err)
	}
}

func TestTicketSigner_BindMismatch(t *testing.T) {
	t.Parallel()
	signer := NewTicketSigner("secret", "", time.Minute, 8)
	ticket, err := signer.Mint(testClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got, err := signer.Unwrap(ticket)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if got.Binds("other", "registry-1", "search", "search", MethodToolsCall) {
		t.Fatal("cross-tenant ticket must not bind")
	}
}

func TestTicketSigner_DisabledRejectsTicket(t *testing.T) {
	t.Parallel()
	enabled := NewTicketSigner("secret", "", time.Minute, 8)
	ticket, err := enabled.Mint(testClaims())
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if _, err := NewTicketSigner("", "", time.Minute, 8).Unwrap(ticket); !errors.Is(err, ErrMRTRReplayRejected) {
		t.Fatalf("err = %v", err)
	}
}
