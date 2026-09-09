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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
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
}

func NewCreator(
	repo domain.Repository,
	manager *cache.TTLMapManager,
	logger *slog.Logger,
	signaler configsyncport.SnapshotSignaler,
	catalog MCPAuthCatalog,
	compilers ...appopenapi.Compiler,
) Creator {
	var compiler appopenapi.Compiler
	if len(compilers) > 0 {
		compiler = compilers[0]
	}
	return &creator{
		repo:        repo,
		memoryCache: manager.GetTTLMap(cache.RegistryTTLName),
		logger:      logger,
		signaler:    signaler,
		catalog:     catalog,
		openapi:     compiler,
	}
}

func (c *creator) Create(ctx context.Context, in CreateInput) (*domain.Registry, error) {
	var b *domain.Registry
	var err error
	if in.Type == domain.TypeMCP {
		in.MCPTarget.Normalize()
		if err := compileOpenAPITarget(ctx, in.MCPTarget, c.openapi); err != nil {
			return nil, err
		}
		if err := CanonicalizeMCPAuthFromCatalog(in.MCPTarget, c.catalog); err != nil {
			return nil, err
		}
		if err := c.refuseSecondInstance(ctx, in.GatewayID, in.MCPTarget); err != nil {
			return nil, err
		}
		b, err = domain.NewMCPRegistry(
			in.GatewayID,
			in.Name,
			in.Description,
			in.MCPTarget,
		)
	} else {
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
	if err != nil {
		return nil, err
	}
	if in.Enabled != nil {
		b.Enabled = *in.Enabled
	}
	if err := c.repo.Save(ctx, b); err != nil {
		return nil, err
	}
	c.memoryCache.Set(b.ID.String(), b)
	if c.signaler != nil {
		c.signaler.Signal(ctx)
	}
	return b, nil
}

// instanceScanPageSize bounds the fallback scan for a gateway's registries when
// the repository offers no catalog-code index.
const instanceScanPageSize = 500

// ErrSingleInstanceServer is returned when a second registry is asked for a
// catalog server that supports only one (see
// catalogdomain.MCPServer.SupportsInstances).
var ErrSingleInstanceServer = fmt.Errorf(
	"registry: this MCP server supports a single instance: %w", commonerrors.ErrConflict,
)

// catalogCodeLister is the indexed lookup the persistent repository offers.
// Without it the check falls back to a page scan of the gateway's registries.
type catalogCodeLister interface {
	ListByGatewayAndCatalogCode(ctx context.Context, gatewayID ids.GatewayID, code string) ([]*domain.Registry, error)
}

// refuseSecondInstance blocks a duplicate of a catalog server that has nothing
// for an operator to configure differently. Instances exist so one server can be
// shelved twice with different configuration — two Snowflake schemas, two Aha!
// domains, two API keys. A server that is a fixed URL behind per-user OAuth has
// none of that, so a second registry would be a copy of the first and would only
// add ambiguity: an instance to pick on every install and uninstall, every tool
// name qualified by its instance, two Access rows granting the same thing.
//
// Only the creation of a new duplicate is refused. A gateway that already holds
// two is left alone — the pair is real, someone is routing to it, and breaking
// that to enforce a rule about what should have been created is not a trade
// worth making.
func (c *creator) refuseSecondInstance(
	ctx context.Context,
	gatewayID ids.GatewayID,
	target *domain.MCPTarget,
) error {
	// A server an operator wired by hand has no catalog entry to read a rule
	// from, so it is theirs to shelve as often as they like.
	if c.catalog == nil || target == nil {
		return nil
	}
	code := strings.TrimSpace(target.Code)
	if code == "" {
		return nil
	}
	entry, ok := c.catalog.GetByCode(code)
	if !ok || entry.SupportsInstances() {
		return nil
	}
	existing, err := c.registriesForCode(ctx, gatewayID, code)
	if err != nil {
		return err
	}
	if len(existing) == 0 {
		return nil
	}
	return fmt.Errorf("%w: %q is already connected as %q",
		ErrSingleInstanceServer, code, existing[0].Name)
}

func (c *creator) registriesForCode(
	ctx context.Context,
	gatewayID ids.GatewayID,
	code string,
) ([]*domain.Registry, error) {
	if indexed, ok := c.repo.(catalogCodeLister); ok {
		items, err := indexed.ListByGatewayAndCatalogCode(ctx, gatewayID, code)
		if err != nil {
			return nil, fmt.Errorf("registry: list by catalog code: %w", err)
		}
		return items, nil
	}
	items, _, err := c.repo.List(ctx, domain.ListFilter{
		GatewayID: gatewayID,
		Page:      1,
		Size:      instanceScanPageSize,
	})
	if err != nil {
		return nil, fmt.Errorf("registry: list gateway registries: %w", err)
	}
	out := make([]*domain.Registry, 0, 1)
	for _, registry := range items {
		if registry != nil && registry.MCPTarget != nil &&
			strings.TrimSpace(registry.MCPTarget.Code) == code {
			out = append(out, registry)
		}
	}
	return out, nil
}

func validateProviderOptions(target *domain.LLMTarget) error {
	if target == nil {
		return nil
	}
	if err := providers.ValidateProviderOptions(target.Provider, target.ProviderOptions); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrInvalidRegistry, err)
	}
	return nil
}
