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

package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"

	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// AuthLookup loads the gateway auth an MCP exchange is pinned to.
type AuthLookup interface {
	FindByID(ctx context.Context, id ids.AuthID) (*authdomain.Auth, error)
}

// GatewayLookup loads the gateway a registry belongs to.
type GatewayLookup interface {
	FindByID(ctx context.Context, id ids.GatewayID) (*gatewaydomain.Gateway, error)
}

// Option configures a registry Creator or Updater.
type Option func(*options)

type options struct {
	openapi appopenapi.Compiler
	auths   AuthLookup
	cards   agentCards
	scanner SkillScanner
	shared  sharedPlane
}

// WithOpenAPICompiler compiles OpenAPI-sourced MCP targets on save.
func WithOpenAPICompiler(c appopenapi.Compiler) Option {
	return func(o *options) { o.openapi = c }
}

// WithAuthLookup lets a save check the gateway auth named by
// mcp_target.auth.identity_id. Without it such a target is refused.
func WithAuthLookup(l AuthLookup) Option {
	return func(o *options) { o.auths = l }
}

// WithAgentCards lets a save of an A2A registry read and pin its agent card.
func WithAgentCards(fetcher CardFetcher, credentials CardCredentials) Option {
	return func(o *options) { o.cards = agentCards{fetcher: fetcher, credentials: credentials} }
}

// WithSkillScanner has TrustGuard score each skill of a card when it is
// pinned, previewed or compared. Without it skills are not scanned.
func WithSkillScanner(s SkillScanner) Option {
	return func(o *options) { o.scanner = s }
}

// WithSharedDataPlane marks the deployment as the shared SaaS one: a save of
// an A2A registry on a gateway no data plane of its own serves applies
// domain.A2ATarget.ValidateSharedDataPlane.
// A nil gateways applies the rules to every gateway, since the gateway cannot
// be shown to have a data plane of its own.
func WithSharedDataPlane(gateways GatewayLookup) Option {
	return func(o *options) { o.shared = sharedPlane{enabled: true, gateways: gateways} }
}

// sharedPlane is whether saves follow the shared data plane rules, and how a
// gateway is found to tell whether a data plane of its own serves it.
type sharedPlane struct {
	enabled  bool
	gateways GatewayLookup
}

func applyOptions(opts []Option) options {
	var o options
	for _, opt := range opts {
		opt(&o)
	}
	o.cards.scanner = o.scanner
	return o
}

// validateExchangeIdentity refuses an identity_id the exchange could never
// use, so the mistake surfaces on save instead of as a failed upstream call.
func validateExchangeIdentity(ctx context.Context, auths AuthLookup, gatewayID ids.GatewayID, target *domain.MCPTarget) error {
	// A misplaced identity_id is the domain validation's to report, with a
	// clearer message than a lookup failure.
	if target == nil || target.Auth == nil || target.Auth.IdentityID == "" || !target.Auth.UsesIdPClient() {
		return nil
	}
	if auths == nil {
		return fmt.Errorf("%w: identity_id cannot be checked here", domain.ErrInvalidMCPTarget)
	}
	id, err := ids.Parse[ids.AuthKind](target.Auth.IdentityID)
	if err != nil {
		return fmt.Errorf("%w: identity_id must be an auth id (uuid)", domain.ErrInvalidMCPTarget)
	}
	// uuid.Parse accepts upper case, braces and urn forms; the exchanger
	// matches the canonical string, so store that.
	target.Auth.IdentityID = id.String()
	a, err := auths.FindByID(ctx, id)
	if errors.Is(err, authdomain.ErrNotFound) || (err == nil && a.GatewayID != gatewayID) {
		return fmt.Errorf("%w: identity_id %s is not an auth of this gateway", domain.ErrInvalidMCPTarget, id)
	}
	if err != nil {
		return fmt.Errorf("load identity %s: %w", id, err)
	}
	if a.Type != authdomain.TypeOAuth2 || a.Config.OAuth2 == nil {
		return fmt.Errorf("%w: identity_id %s must reference an oauth2 auth", domain.ErrInvalidMCPTarget, id)
	}
	if !a.Enabled {
		return fmt.Errorf("%w: identity_id %s references a disabled auth", domain.ErrInvalidMCPTarget, id)
	}
	cfg := a.Config.OAuth2
	if _, _, ok := cfg.ExchangeCredentials(); !ok || strings.TrimSpace(cfg.Issuer) == "" {
		return fmt.Errorf("%w: identity_id %s needs an issuer and exchange client credentials to sign the exchange",
			domain.ErrInvalidMCPTarget, id)
	}
	if cfg.SessionMode && cfg.Interactive() {
		return fmt.Errorf("%w: identity_id %s signs people in with gateway session tokens (session_mode), "+
			"which the identity provider cannot exchange; turn session mode off on that identity",
			domain.ErrInvalidMCPTarget, id)
	}
	return nil
}

func validateSharedDataPlane(ctx context.Context, shared sharedPlane, gatewayID ids.GatewayID, t *domain.A2ATarget) error {
	if !shared.enabled {
		return nil
	}
	if shared.gateways != nil {
		gw, err := shared.gateways.FindByID(ctx, gatewayID)
		if err != nil {
			return err
		}
		if gw.ServedByOwnDataPlane() {
			return nil
		}
	}
	return t.ValidateSharedDataPlane()
}
