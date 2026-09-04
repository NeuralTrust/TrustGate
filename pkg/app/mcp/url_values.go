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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	vaultdomain "github.com/NeuralTrust/TrustGate/pkg/domain/vault"
)

// URLValueResolver returns the per-user values for a registry's URL placeholders
// (e.g. {account_url}, {instance}), keyed by variable name, for the calling
// principal. Plain values come from the principal's install config; the resolver
// returns what it has and lets ResolveURL decide whether a required placeholder
// is unfilled — so a half-configured server fails to dial with a clear error
// rather than silently hitting a broken URL.
type URLValueResolver interface {
	Resolve(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) (map[string]string, error)
}

// installationConfigFinder is the read the resolver needs: the calling
// principal's installation for a catalog code, whose Config carries their plain
// URL variable values. installationdomain.Repository satisfies it.
type installationConfigFinder interface {
	Find(ctx context.Context, gatewayID ids.GatewayID, principalSub, catalogCode string) (*installationdomain.Installation, error)
}

// urlVarSecretFinder reads a secret URL variable's per-user value from the vault.
// vaultdomain.Repository satisfies it.
type urlVarSecretFinder interface {
	Find(ctx context.Context, gatewayID ids.GatewayID, principalSub, provider string) (*vaultdomain.Credential, error)
}

type urlValueResolver struct {
	installs installationConfigFinder
	vault    urlVarSecretFinder
}

// NewURLValueResolver builds the resolver over the installation store (plain
// values the user supplied at install) and the vault (secret values entered
// through the connect link). vault may be nil, in which case secret variables are
// left unfilled and ResolveURL fails closed for a server that requires one.
func NewURLValueResolver(installs installationConfigFinder, vault urlVarSecretFinder) URLValueResolver {
	return &urlValueResolver{installs: installs, vault: vault}
}

func (r *urlValueResolver) Resolve(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
) (map[string]string, error) {
	if r == nil || r.installs == nil || rc == nil || rc.Consumer == nil || reg == nil || reg.MCPTarget == nil {
		return nil, nil
	}
	principal := identity.PrincipalFromContext(ctx)
	if principal == nil || principal.Subject == "" {
		return nil, ErrNoPrincipal
	}
	gatewayID := rc.Consumer.GatewayID
	code := reg.MCPTarget.Code

	values := map[string]string{}
	inst, err := r.installs.Find(ctx, gatewayID, principal.Subject, code)
	switch {
	case err == nil:
		for k, v := range inst.Config {
			values[k] = v
		}
	case errors.Is(err, installationdomain.ErrNotFound):
		// The principal has not configured this server; leave the plain values
		// empty so ResolveURL surfaces the missing required placeholders.
	default:
		return nil, err
	}

	// Secret variables never touch the install config; they are read per-user from
	// the vault, where the connect link stored them. A missing one is left unset so
	// ResolveURL fails closed rather than dialing a half-formed URL.
	if r.vault != nil {
		for _, v := range reg.MCPTarget.URLVariables {
			if !v.Secret {
				continue
			}
			cred, err := r.vault.Find(ctx, gatewayID, principal.Subject, registrydomain.URLVariableVaultProvider(code, v.Name))
			if err != nil {
				if errors.Is(err, vaultdomain.ErrNotFound) {
					continue
				}
				return nil, err
			}
			if cred != nil && cred.AccessToken != "" {
				values[v.Name] = cred.AccessToken
			}
		}
	}
	return values, nil
}
