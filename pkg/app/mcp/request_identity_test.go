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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
	vaultmocks "github.com/NeuralTrust/TrustGate/pkg/domain/vault/mocks"
	"github.com/stretchr/testify/mock"
)

func TestConnectedAccountEmail_UniqueEmail(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	vault := vaultmocks.NewRepository(t)
	vault.EXPECT().
		ListByPrincipal(mock.Anything, gw, "alice").
		Return([]*vaultdomain.Credential{
			{AccountRef: "ada@example.com", Provider: "google"},
			{AccountRef: "ada@example.com", Provider: "github"},
		}, nil).
		Once()

	got := ConnectedAccountEmail(context.Background(), vault, gw, "alice")
	if got != "ada@example.com" {
		t.Fatalf("ConnectedAccountEmail = %q, want ada@example.com", got)
	}
}

func TestConnectedAccountEmail_DistinctEmailsAreAmbiguous(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	vault := vaultmocks.NewRepository(t)
	vault.EXPECT().
		ListByPrincipal(mock.Anything, gw, "alice").
		Return([]*vaultdomain.Credential{
			{AccountRef: "ada@example.com", Provider: "google"},
			{AccountRef: "ada@github.com", Provider: "github"},
		}, nil).
		Once()

	got := ConnectedAccountEmail(context.Background(), vault, gw, "alice")
	if got != "" {
		t.Fatalf("ConnectedAccountEmail = %q, want empty when accounts disagree", got)
	}
}

func TestConnectedAccountEmail_IgnoresNonEmailRefs(t *testing.T) {
	t.Parallel()
	refs := []*vaultdomain.Credential{
		{AccountRef: "octocat"},
		{AccountRef: ""},
		nil,
	}
	if got := uniqueAccountEmail(refs); got != "" {
		t.Fatalf("uniqueAccountEmail = %q, want empty", got)
	}
}

func TestConnectedAccountEmail_NilVault(t *testing.T) {
	t.Parallel()
	if got := ConnectedAccountEmail(context.Background(), nil, ids.New[ids.GatewayKind](), "alice"); got != "" {
		t.Fatalf("ConnectedAccountEmail = %q, want empty", got)
	}
}
