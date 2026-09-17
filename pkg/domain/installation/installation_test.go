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

package installation

import (
	"errors"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestNewInstallation(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in, err := New(gw, "user-1", "github", "user-1", map[string]string{"host": "gh.acme.internal"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if in.ID == (ids.InstallationID{}) {
		t.Fatal("installation must get a generated id")
	}
	if in.GatewayID != gw || in.PrincipalSub != "user-1" || in.CatalogCode != "github" {
		t.Fatalf("unexpected fields: %+v", in)
	}
	if in.Status != StatusInstalled || !in.IsActive() {
		t.Fatalf("New must start installed/active, got %q", in.Status)
	}
	if in.Config["host"] != "gh.acme.internal" {
		t.Fatalf("per-user config must be carried, got %+v", in.Config)
	}
	if in.CreatedAt.IsZero() || in.UpdatedAt.IsZero() {
		t.Fatal("timestamps must be set")
	}
}

func TestNewInstallationValidation(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	cases := []struct {
		name         string
		gatewayID    ids.GatewayID
		principalSub string
		catalogCode  string
	}{
		{"nil gateway", ids.GatewayID{}, "user-1", "github"},
		{"empty principal", gw, "  ", "github"},
		{"empty code", gw, "user-1", ""},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.gatewayID, tc.principalSub, tc.catalogCode, "actor", nil)
			if err == nil {
				t.Fatal("expected a validation error")
			}
			if !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("error must wrap ErrValidation, got %v", err)
			}
		})
	}
}

func TestInstallationIsActiveOnlyWhenInstalled(t *testing.T) {
	if (&Installation{Status: StatusPendingApproval}).IsActive() {
		t.Fatal("pending_approval must not be active")
	}
	if (&Installation{Status: StatusRevoked}).IsActive() {
		t.Fatal("revoked must not be active")
	}
	if !(&Installation{Status: StatusInstalled}).IsActive() {
		t.Fatal("installed must be active")
	}
	if (*Installation)(nil).IsActive() {
		t.Fatal("nil must not be active")
	}
}
