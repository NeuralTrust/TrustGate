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
	"fmt"
	"log/slog"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

type CreateInput struct {
	GatewayID   ids.GatewayID
	Name        string
	Type        domain.Type
	Enabled     *bool
	Description string
	LLMTarget   *domain.LLMTarget
	MCPTarget   *domain.MCPTarget
	A2ATarget   *domain.A2ATarget
	// Managed creates an LLM registry NeuralTrust supplies the credentials for.
	// Only the platform may ask for it (see AsPlatform).
	Managed bool
}

//go:generate mockery --name=Creator --dir=. --output=./mocks --filename=registry_creator_mock.go --case=underscore --with-expecter
type Creator interface {
	Create(ctx context.Context, in CreateInput) (*domain.Registry, error)
}

var _ Creator = (*creator)(nil)

type creator struct {
	repo        domain.Repository
	memoryCache *cache.TTLMap
	logger      *slog.Logger
	signaler    configsyncport.SnapshotSignaler
	catalog     MCPAuthCatalog
	openapi     appopenapi.Compiler
	auths       AuthLookup
	cards       agentCards
	shared      sharedPlane
	secretRefs  SecretRefValidator
}

func NewCreator(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	catalog MCPAuthCatalog,
	opts ...Option,
) Creator {
	o := applyOptions(opts)
	return &creator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
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

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Registry, error) {
	if err := refuseManagedChange(ctx, in.Managed); err != nil {
		return nil, err
	}
	var b *domain.Registry
	var err error
	switch {
	case in.Managed && in.Type != domain.TypeLLM && in.Type != "":
		return nil, fmt.Errorf("%w: only an LLM registry can be managed", domain.ErrInvalidRegistry)
	case in.Managed:
		if verr := validateProviderOptions(in.LLMTarget); verr != nil {
			return nil, verr
		}
		b, err = domain.NewManagedLLMRegistry(in.GatewayID, in.Name, in.Description, in.LLMTarget)
	}
	if b == nil && err == nil {
		b, err = c.build(ctx, in)
	}
	if err != nil {
		return nil, err
	}
	if in.Enabled != nil {
		b.Enabled = *in.Enabled
	}
	audit := func() {}
	if c.secretRefs != nil {
		if audit, err = c.secretRefs.ValidateRegistry(ctx, b, nil); err != nil {
			return nil, err
		}
	}
	if err := c.repo.Save(ctx, b); err != nil {
		return nil, err
	}
	audit()
	c.memoryCache.Set(b.ID.String(), b)
	if c.signaler != nil {
		c.signaler.Signal(ctx)
	}
	return b, nil
}

// build makes a registry the tenant supplies the credentials for.
func (c *creator) build(ctx context.Context, in CreateInput) (*domain.Registry, error) {
	var b *domain.Registry
	var err error
	switch in.Type {
	case domain.TypeA2A:
		if err := c.prepareA2A(ctx, in); err != nil {
			return nil, err
		}
		b, err = domain.NewA2ARegistry(in.GatewayID, in.Name, in.Description, in.A2ATarget)
	case domain.TypeMCP:
		in.MCPTarget.Normalize()
		if err := compileOpenAPITarget(ctx, in.MCPTarget, c.openapi); err != nil {
			return nil, err
		}
		if err := CanonicalizeMCPAuthFromCatalog(in.MCPTarget, c.catalog); err != nil {
			return nil, err
		}
		// The gateway's own first-install shelf is the catalog template. An
		// admin save is the path that has to fill non-secret placeholders.
		if in.MCPTarget.Origin != domain.MCPOriginStore {
			if err := RequireAdminBoundURLVariables(in.MCPTarget, c.catalog); err != nil {
				return nil, err
			}
		}
		if err := validateExchangeIdentity(ctx, c.auths, in.GatewayID, in.MCPTarget); err != nil {
			return nil, err
		}
		b, err = domain.NewMCPRegistry(
			in.GatewayID,
			in.Name,
			in.Description,
			in.MCPTarget,
		)
	default:
		if verr := validateProviderOptions(in.LLMTarget); verr != nil {
			return nil, verr
		}
		b, err = domain.NewLLMRegistry(
			in.GatewayID,
			in.Name,
			in.Description,
			in.LLMTarget,
		)
	}
	return b, err
}

// prepareA2A validates the target before any request leaves the gateway,
// then reads and pins its card.
func (c *creator) prepareA2A(ctx context.Context, in CreateInput) error {
	in.A2ATarget.Normalize()
	if err := in.A2ATarget.Validate(); err != nil {
		return err
	}
	if err := validateSharedDataPlane(ctx, c.shared, in.GatewayID, in.A2ATarget); err != nil {
		return err
	}
	if err := validateExchangeIdentity(ctx, c.auths, in.GatewayID, &domain.MCPTarget{Auth: in.A2ATarget.Auth}); err != nil {
		return err
	}
	return c.cards.pin(ctx, in.GatewayID, in.A2ATarget)
}

func validateProviderOptions(target *domain.LLMTarget) error {
	if target == nil {
		return nil
	}
	if err := providers.ValidateProviderOptions(target.Provider, target.ProviderOptions); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrInvalidRegistry, err)
	}
	if name, masked := domain.MaskedProviderOptionHeader(target.ProviderOptions); masked {
		return fmt.Errorf("%w: provider_options.headers[%s] cannot be a masked value", domain.ErrInvalidRegistry, name)
	}
	return nil
}
