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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

func ConnectedAccountEmail(ctx context.Context, vault vaultdomain.Repository, gatewayID ids.GatewayID, principalSub string) string {
	if vault == nil || principalSub == "" || gatewayID.IsNil() {
		return ""
	}
	creds, err := vault.ListByPrincipal(ctx, gatewayID, principalSub)
	if err != nil {
		return ""
	}
	return uniqueAccountEmail(creds)
}

func uniqueAccountEmail(creds []*vaultdomain.Credential) string {
	seen := make(map[string]string, len(creds))
	for _, cred := range creds {
		if cred == nil {
			continue
		}
		ref := strings.TrimSpace(cred.AccountRef)
		if !identity.LooksLikeEmail(ref) {
			continue
		}
		key := strings.ToLower(ref)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = ref
	}
	if len(seen) != 1 {
		return ""
	}
	for _, ref := range seen {
		return ref
	}
	return ""
}
