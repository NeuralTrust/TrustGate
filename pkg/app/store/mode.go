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

package store

import (
	"context"
	"log/slog"
	"strings"

	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// ModeResolver decides the Store mode that applies to the calling principal on
// a gateway, live on every request: the admin's per-principal policy (their
// own, else the most permissive of their groups'), then the legacy token claim,
// then the gateway default. Because the policy is read here rather than baked
// into the token at login, a change on the Access page applies at once.
type ModeResolver interface {
	Mode(ctx context.Context, gatewayID ids.GatewayID) string
}

// ModeQuery contains the explicit inputs used to resolve Store access.
type ModeQuery struct {
	GatewayID ids.GatewayID
	Subject   string
	Groups    []string
	Fallback  string
}

type queryModeResolver interface {
	Resolve(ctx context.Context, query ModeQuery) string
}

type modeResolver struct {
	policies storeaccessdomain.PolicyReader
}

// NewModeResolver wires the live resolver over the gateway's policies. A nil
// reader (a plane without policies) resolves like EffectiveStoreMode.
func NewModeResolver(policies storeaccessdomain.PolicyReader) ModeResolver {
	return &modeResolver{policies: policies}
}

func (r *modeResolver) Mode(ctx context.Context, gatewayID ids.GatewayID) string {
	principal := identity.PrincipalFromContext(ctx)
	query := ModeQuery{GatewayID: gatewayID, Fallback: EffectiveStoreMode(ctx)}
	if principal != nil {
		query.Subject = principal.Subject
		query.Groups = principal.Groups()
	}
	return r.Resolve(ctx, query)
}

func (r *modeResolver) Resolve(ctx context.Context, query ModeQuery) string {
	if r != nil && r.policies != nil && strings.TrimSpace(query.Subject) != "" && !query.GatewayID.IsNil() {
		policies, err := r.policies.ListPoliciesByGateway(ctx, query.GatewayID)
		if err != nil {
			slog.WarnContext(ctx, "store: policy lookup failed; failing closed to curated",
				slog.String("gateway_id", query.GatewayID.String()), slog.String("error", err.Error()))
			return gatewaydomain.StoreModeCurated
		}
		if mode := storeaccessdomain.IndexPolicies(policies).Mode(strings.TrimSpace(query.Subject), query.Groups); mode != "" {
			return mode
		}
	}
	return normalizeMode(query.Fallback)
}

// ResolveMode resolves a Store mode from explicit identity and gateway inputs.
func ResolveMode(ctx context.Context, r ModeResolver, query ModeQuery) string {
	if r == nil {
		return normalizeMode(query.Fallback)
	}
	if resolver, ok := r.(queryModeResolver); ok {
		return resolver.Resolve(ctx, query)
	}
	legacy := identity.WithPrincipal(ctx, &identity.Principal{
		Subject: query.Subject,
		Claims: map[string]any{
			identity.ClaimGroups:      query.Groups,
			identity.ClaimStoreAccess: normalizeMode(query.Fallback),
		},
	})
	return r.Mode(legacy, query.GatewayID)
}

func normalizeMode(mode string) string {
	switch mode {
	case gatewaydomain.StoreModeOpen, gatewaydomain.StoreModeNone:
		return mode
	default:
		return gatewaydomain.StoreModeCurated
	}
}

// EffectiveStoreMode is the Store access that applies to the calling principal
// when no live policy names them: the legacy per-principal store_access claim
// (open/curated/none) when a token still carries one, otherwise the gateway's
// stamped default. Without a resolved gateway in the context the mode is
// unknown, so it fails closed to curated rather than opening the Store. Services
// go through ModeResolver, which consults the gateway's policies first.
//
// The three modes are the whole governance model:
//   - open ("All"): every catalog server installs instantly;
//   - curated ("Selected"): what is granted to the principal installs
//     instantly, anything else becomes an approval request;
//   - none: nothing is browsable or installable.
func EffectiveStoreMode(ctx context.Context) string {
	switch identity.PrincipalFromContext(ctx).StoreAccess() {
	case gatewaydomain.StoreModeOpen:
		return gatewaydomain.StoreModeOpen
	case gatewaydomain.StoreModeCurated:
		return gatewaydomain.StoreModeCurated
	case gatewaydomain.StoreModeNone:
		return gatewaydomain.StoreModeNone
	}
	if gw, ok := appgateway.FromContext(ctx); ok && gw != nil {
		return gw.StoreMode()
	}
	return gatewaydomain.StoreModeCurated
}
