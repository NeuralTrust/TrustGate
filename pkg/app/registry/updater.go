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
	"cmp"
	"context"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"strings"
	"time"

	appsecretref "github.com/NeuralTrust/TrustGate/pkg/app/secretref"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/app/invalidation"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

type UpdateInput struct {
	ID              ids.RegistryID
	GatewayID       ids.GatewayID
	Name            *string
	Enabled         *bool
	Provider        *string
	ProviderOptions *map[string]any
	Description     *string
	Auth            *domain.TargetAuth
	HealthChecks    *domain.HealthChecks
	Pricing         *domain.Pricing
	SetPricing      bool
	MCPTarget       *domain.MCPTarget
	A2ATarget       *domain.A2ATarget
}

//go:generate mockery --name=Updater --dir=. --output=./mocks --filename=registry_updater_mock.go --case=underscore --with-expecter
type Updater interface {
	Update(ctx context.Context, in UpdateInput) (*domain.Registry, error)
}

var _ Updater = (*updater)(nil)

type updater struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	publisher   cache.EventPublisher
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
	catalog     MCPAuthCatalog
	openapi     appopenapi.Compiler
	auths       AuthLookup
	cards       agentCards
	shared      sharedPlane
	secretRefs  SecretRefValidator
}

func NewUpdater(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	publisher cache.EventPublisher,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	catalog MCPAuthCatalog,
	opts ...Option,
) Updater {
	o := applyOptions(opts)
	return &updater{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		publisher:   publisher,
		logger:      logger,
		signaler:    signaler,
		catalog:     catalog,
		openapi:     o.openapi,
		auths:       o.auths,
		cards:       o.cards,
		shared:      o.shared,
		secretRefs:  o.secretRefs,
	}
}

func (u *updater) Update(ctx context.Context, in UpdateInput) (*domain.Registry, error) {
	existing, err := u.repo.FindByID(ctx, in.ID)
	if err != nil {
		return nil, err
	}
	if !in.GatewayID.IsNil() && in.GatewayID != existing.GatewayID {
		return nil, domain.ErrInvalidGatewayID
	}
	if err := refuseManagedChange(ctx, existing.Managed); err != nil {
		return nil, err
	}
	if in.Name != nil {
		existing.Name = *in.Name
	}
	if in.Description != nil {
		existing.Description = *in.Description
	}
	if in.Enabled != nil {
		existing.Enabled = *in.Enabled
	}
	storedRefs, storedEmbedded := appsecretref.RegistryReferences(existing)
	storedRefs = append(storedRefs, storedEmbedded...)
	applyLLMTargetUpdate(existing, in)
	prevAuth := storedMCPAuth(existing)
	if err := applyMCPTargetUpdate(ctx, existing, in, u.catalog, u.openapi); err != nil {
		return nil, err
	}
	if exchangeIdentityChanged(prevAuth, storedMCPAuth(existing)) {
		if err := validateExchangeIdentity(ctx, u.auths, existing.GatewayID, existing.MCPTarget); err != nil {
			return nil, err
		}
	}
	if err := u.applyA2ATargetUpdate(ctx, existing, in.A2ATarget); err != nil {
		return nil, err
	}
	existing.UpdatedAt = time.Now().UTC()
	if !existing.IsMCP() {
		if verr := validateProviderOptions(existing.LLMTarget); verr != nil {
			return nil, verr
		}
	}
	if err := existing.Validate(); err != nil {
		return nil, err
	}
	audit := func() {}
	if u.secretRefs != nil {
		if audit, err = u.secretRefs.ValidateRegistry(ctx, existing, storedRefs); err != nil {
			return nil, err
		}
	}
	if err := u.repo.Update(ctx, existing); err != nil {
		return nil, err
	}
	audit()
	u.memoryCache.Set(existing.ID.String(), existing)
	invalidation.Registry(ctx, u.publisher, u.logger, existing.GatewayID, existing.ID)
	if u.signaler != nil {
		u.signaler.Signal(ctx)
	}
	return existing, nil
}

// applyA2ATargetUpdate merges incoming over the stored target: omitted fields
// keep their stored value, masked secrets resolve to the stored ones, and the
// card is read and pinned again only when card_url, protocol_version or the
// locator changes.
func (u *updater) applyA2ATargetUpdate(ctx context.Context, existing *domain.Registry, incoming *domain.A2ATarget) error {
	if incoming == nil {
		return nil
	}
	prev := existing.A2ATarget
	if existing.Type != domain.TypeA2A || prev == nil {
		return fmt.Errorf("%w: a2a_target is only valid for A2A registries", domain.ErrInvalidRegistry)
	}
	if incoming.Provider != "" && incoming.Provider != prev.Provider {
		return fmt.Errorf("%w: a registry cannot change provider; create another registry", domain.ErrInvalidRegistry)
	}
	next := *incoming
	next.Provider = prev.Provider
	next.CardURL = cmp.Or(strings.TrimSpace(next.CardURL), prev.CardURL)
	next.ProtocolVersion = cmp.Or(next.ProtocolVersion, prev.ProtocolVersion)
	next.URL = cmp.Or(strings.TrimSpace(next.URL), prev.URL)
	next.BedrockAgentCore = cmp.Or(next.BedrockAgentCore, prev.BedrockAgentCore)
	next.AzureFoundry = cmp.Or(next.AzureFoundry, prev.AzureFoundry)
	next.VertexAgentEngine = cmp.Or(next.VertexAgentEngine, prev.VertexAgentEngine)
	next.AgentCoreHarness = cmp.Or(next.AgentCoreHarness, prev.AgentCoreHarness)
	next.Databricks = cmp.Or(next.Databricks, prev.Databricks)
	next.Auth = cmp.Or(next.Auth, prev.Auth)
	if next.CardAuth == "" && next.CardAuthApplies(prev.CardAuth) {
		next.CardAuth = prev.CardAuth
	}
	if next.CloudAuth == nil && next.NeedsCloudAuth() {
		next.CloudAuth = prev.CloudAuth
	}
	if next.Headers == nil {
		next.Headers = prev.Headers
	}
	if next.AllowedMethods == nil {
		next.AllowedMethods = prev.AllowedMethods
	}
	next.ResolvedCardURL, next.Card, next.CardDigest, next.CardPinnedAt = prev.ResolvedCardURL, prev.Card, prev.CardDigest, prev.CardPinnedAt
	next.Normalize()
	next.ResolveSecretsFrom(prev)
	if err := next.Validate(); err != nil {
		return err
	}
	if err := validateSharedDataPlane(ctx, u.shared, existing.GatewayID, &next); err != nil {
		return err
	}
	if exchangeIdentityChanged(prev.Auth, next.Auth) {
		if err := validateExchangeIdentity(ctx, u.auths, existing.GatewayID, &domain.MCPTarget{Auth: next.Auth}); err != nil {
			return err
		}
	}
	if next.CardURL != prev.CardURL || next.ProtocolVersion != prev.ProtocolVersion || !sameLocator(&next, prev) {
		if err := u.cards.pin(ctx, existing.GatewayID, &next); err != nil {
			return err
		}
	}
	existing.A2ATarget = &next
	return nil
}

func sameLocator(a, b *domain.A2ATarget) bool {
	return samePointee(a.BedrockAgentCore, b.BedrockAgentCore) &&
		samePointee(a.AzureFoundry, b.AzureFoundry) &&
		samePointee(a.VertexAgentEngine, b.VertexAgentEngine) &&
		samePointee(a.AgentCoreHarness, b.AgentCoreHarness) &&
		samePointee(a.Databricks, b.Databricks)
}

func samePointee[T comparable](a, b *T) bool {
	return a == b || (a != nil && b != nil && *a == *b)
}

func applyMCPTargetUpdate(
	ctx context.Context,
	existing *domain.Registry,
	in UpdateInput,
	catalog MCPAuthCatalog,
	compiler appopenapi.Compiler,
) error {
	if in.MCPTarget == nil {
		return nil
	}
	incoming := in.MCPTarget
	if prev := existing.MCPTarget; prev != nil {
		sourceChanged := incoming.Source != "" && normalizedMCPSource(incoming.Source) != normalizedMCPSource(prev.Source)
		if incoming.Source == "" {
			incoming.Source = prev.Source
		}
		// A masked URL is the read API's rendering of the stored one (a secret
		// URL variable shown as ***xxxx), echoed back by a client that edited
		// other fields — the same round-trip secret.Resolve handles for auth
		// secrets. Persisting it would replace the real token with the mask.
		if strings.TrimSpace(incoming.URL) == "" || urlCarriesMaskedSecret(incoming.URL) {
			incoming.URL = prev.URL
		}
		if incoming.Transport == "" {
			incoming.Transport = prev.Transport
		}
		if incoming.Headers == nil {
			incoming.Headers = prev.Headers
		}
		if incoming.Auth == nil {
			incoming.Auth = prev.Auth
		}
		if strings.TrimSpace(incoming.Code) == "" {
			incoming.Code = prev.Code
		}
		// Origin is gateway-owned: an admin renaming or re-authing the default
		// instance keeps it recognisable as the one the gateway materialised.
		incoming.Origin = prev.Origin
		if incoming.OpenAPI == nil && !sourceChanged {
			incoming.OpenAPI = prev.OpenAPI
		}
	}
	incoming.Normalize()
	if err := compileOpenAPITarget(ctx, incoming, compiler); err != nil {
		return err
	}
	incoming.ResolveSecretsFrom(existing.MCPTarget)
	if err := CanonicalizeMCPAuthFromCatalog(incoming, catalog); err != nil {
		return err
	}
	if err := RequireAdminBoundURLVariables(incoming, catalog); err != nil {
		return err
	}
	existing.MCPTarget = incoming
	return nil
}

// urlCarriesMaskedSecret reports whether an mcp_target.url holds a masked
// secret — the redaction marker as (a prefix of) any query value or path
// segment — i.e. it is the read API's masked form, not a new value.
func urlCarriesMaskedSecret(raw string) bool {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return strings.Contains(raw, secret.Redacted)
	}
	for _, values := range u.Query() {
		for _, v := range values {
			if secret.IsMasked(v) {
				return true
			}
		}
	}
	for _, segment := range strings.Split(u.Path, "/") {
		if secret.IsMasked(segment) {
			return true
		}
	}
	return false
}

func normalizedMCPSource(source domain.MCPSource) domain.MCPSource {
	if source == "" {
		return domain.MCPSourceRemote
	}
	return source
}

func applyLLMTargetUpdate(existing *domain.Registry, in UpdateInput) {
	if in.Provider == nil && in.ProviderOptions == nil && in.Auth == nil && in.HealthChecks == nil && !in.SetPricing {
		return
	}
	if existing.LLMTarget == nil {
		existing.LLMTarget = &domain.LLMTarget{}
	}
	target := existing.LLMTarget
	if in.Provider != nil {
		target.Provider = *in.Provider
	}
	if in.ProviderOptions != nil {
		opts := maps.Clone(*in.ProviderOptions)
		target.UnreadableProviderHeaders = domain.ResolveProviderOptionHeaders(opts, target.ProviderOptions, target.UnreadableProviderHeaders)
		target.ProviderOptions = opts
	}
	if in.Auth != nil {
		in.Auth.ResolveSecretsFrom(target.Auth)
		target.Auth = in.Auth
	}
	if in.HealthChecks != nil {
		in.HealthChecks.ResolveSecretsFrom(target.HealthChecks)
		target.HealthChecks = in.HealthChecks
	}
	if in.SetPricing {
		target.Pricing = in.Pricing
	}
}

func storedMCPAuth(r *domain.Registry) *domain.MCPAuth {
	if r.MCPTarget == nil || r.MCPTarget.Auth == nil {
		return nil
	}
	a := *r.MCPTarget.Auth
	return &a
}

// exchangeIdentityChanged limits the identity check to a pin this request
// introduces. Re-sending the stored one, as a client echoing a read does,
// must not refuse unrelated edits because the identity has since gone; the
// exchange refuses that at call time.
func exchangeIdentityChanged(prev, next *domain.MCPAuth) bool {
	if next == nil || next.IdentityID == "" || !next.UsesIdPClient() {
		return false
	}
	if prev == nil || !prev.UsesIdPClient() {
		return true
	}
	return !strings.EqualFold(prev.IdentityID, next.IdentityID)
}
