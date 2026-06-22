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

package vault

import (
	"errors"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestNewCredential_HappyPath(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	c, err := NewCredential(gw, "user-1", "github", "octocat", "tok", "ref", []string{"repo"}, time.Now().Add(time.Hour))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.ID.IsNil() {
		t.Fatal("ID not generated")
	}
	if c.Expired(0) {
		t.Fatal("fresh credential reported expired")
	}
}

func TestNewCredential_Rejects(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	tests := []struct {
		name string
		fn   func() (*Credential, error)
	}{
		{"nil gateway", func() (*Credential, error) {
			return NewCredential(ids.GatewayID{}, "u", "github", "", "t", "", nil, time.Time{})
		}},
		{"empty principal", func() (*Credential, error) {
			return NewCredential(gw, " ", "github", "", "t", "", nil, time.Time{})
		}},
		{"empty provider", func() (*Credential, error) {
			return NewCredential(gw, "u", "", "", "t", "", nil, time.Time{})
		}},
		{"empty access token", func() (*Credential, error) {
			return NewCredential(gw, "u", "github", "", "", "", nil, time.Time{})
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tc.fn(); !errors.Is(err, ErrInvalidCredential) {
				t.Fatalf("error = %v, want ErrInvalidCredential", err)
			}
		})
	}
}

func TestCredential_Expired(t *testing.T) {
	t.Parallel()
	c := &Credential{ExpiresAt: time.Now().Add(30 * time.Second)}
	if c.Expired(0) {
		t.Fatal("expired before expiry without skew")
	}
	if !c.Expired(time.Minute) {
		t.Fatal("not expired within skew window")
	}
	noExpiry := &Credential{}
	if noExpiry.Expired(time.Hour) {
		t.Fatal("credential without expiry reported expired")
	}
}
