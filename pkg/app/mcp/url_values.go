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
// principal's installation for a catalog code, whose Config carries their URL
// variable values. installationdomain.Repository satisfies it.
type installationConfigFinder interface {
	Find(ctx context.Context, gatewayID ids.GatewayID, principalSub, catalogCode string) (*installationdomain.Installation, error)
}

type urlValueResolver struct {
	installs installationConfigFinder
}

// NewURLValueResolver builds the resolver over the installation store. installs
// is the same per-principal store the Store installer writes to, so a value the
// user supplied at install time is exactly what fills the URL at dial time.
func NewURLValueResolver(installs installationConfigFinder) URLValueResolver {
	return &urlValueResolver{installs: installs}
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
	inst, err := r.installs.Find(ctx, rc.Consumer.GatewayID, principal.Subject, reg.MCPTarget.Code)
	if err != nil {
		if errors.Is(err, installationdomain.ErrNotFound) {
			// The principal has not configured this server; leave the values empty
			// so ResolveURL surfaces the missing required placeholders.
			return nil, nil
		}
		return nil, err
	}
	return inst.Config, nil
}
