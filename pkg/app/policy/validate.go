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

package policy

import (
	"context"
	"errors"
	"fmt"
	"slices"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// validatePlugin runs ValidateSettingsWrite only when settingsWritten is true:
// on create, and on an update that carries settings. previous is the
// settings as they were stored immediately before this write - nil on
// create, and nil on a slug change, since settings belonging to the policy's
// previous plugin are not a previous version of the new one's; the caller
// decides that, this only forwards what it is given.
func validatePlugin(
	reg appplugins.Registry,
	slug string,
	stages []domain.Stage,
	mode domain.Mode,
	settings map[string]any,
	previous map[string]any,
	settingsWritten bool,
) error {
	if err := reg.ValidateStages(slug, stages); err != nil {
		return errors.Join(commonerrors.ErrValidation, err)
	}
	if err := reg.ValidateMode(slug, mode); err != nil {
		return errors.Join(commonerrors.ErrValidation, err)
	}
	if err := reg.Validate(slug, settings); err != nil {
		return errors.Join(commonerrors.ErrValidation, err)
	}
	if settingsWritten {
		if err := reg.ValidateSettingsWrite(slug, settings, previous); err != nil {
			return errors.Join(commonerrors.ErrValidation, err)
		}
	}
	return nil
}

// validateMCPScope runs only when a scope arrives in the input. The "at least
// one entry" rule lives here rather than in MCPScope.Validate so a policy
// pruned to {} by a registry delete can still be renamed.
func validateMCPScope(
	ctx context.Context,
	registryRepo registrydomain.Repository,
	pluginReg appplugins.Registry,
	gatewayID ids.GatewayID,
	slug string,
	scope *domain.MCPScope,
) error {
	if scope == nil {
		return nil
	}
	scope.Normalize()
	if err := scope.Validate(); err != nil {
		return err
	}
	if scope.IsEmpty() {
		return fmt.Errorf("%w: scope has no entries", domain.ErrInvalidMCPScope)
	}
	if err := validateMCPScopePlugin(pluginReg, slug); err != nil {
		return err
	}
	return validateMCPScopeRegistries(ctx, registryRepo, gatewayID, scope)
}

func validateMCPScopePlugin(reg appplugins.Registry, slug string) error {
	if pluginRunsOnMCP(reg, slug) {
		return nil
	}
	return fmt.Errorf("%w: plugin %s does not support protocol %s", domain.ErrInvalidMCPScope, slug, appplugins.ProtocolMCP)
}

func validateMCPWidePlugin(reg appplugins.Registry, slug string) error {
	if pluginRunsOnMCP(reg, slug) {
		return nil
	}
	return fmt.Errorf("%w: plugin %s does not support protocol %s", domain.ErrMCPWideUnsupported, slug, appplugins.ProtocolMCP)
}

// pluginRunsOnMCP lets an unknown slug through: that is not a protocol
// question, and validatePlugin refuses it wherever a slug is written.
func pluginRunsOnMCP(reg appplugins.Registry, slug string) bool {
	p, ok := reg.Get(slug)
	if !ok {
		return true
	}
	return slices.Contains(p.SupportedProtocols(), appplugins.ProtocolMCP)
}

func validateMCPScopeRegistries(
	ctx context.Context,
	repo registrydomain.Repository,
	gatewayID ids.GatewayID,
	scope *domain.MCPScope,
) error {
	wanted := scopeRegistryIDs(scope)
	if len(wanted) == 0 {
		return nil
	}
	found, err := repo.FindByIDs(ctx, gatewayID, wanted)
	if err != nil {
		return err
	}
	byID := make(map[ids.RegistryID]*registrydomain.Registry, len(found))
	for _, reg := range found {
		if reg != nil {
			byID[reg.ID] = reg
		}
	}
	for _, id := range wanted {
		reg, ok := byID[id]
		if !ok {
			return fmt.Errorf("%w: registry %s not found in gateway %s", domain.ErrInvalidMCPScope, id, gatewayID)
		}
		if !reg.IsMCP() {
			return fmt.Errorf("%w: registry %s is not an MCP registry", domain.ErrInvalidMCPScope, id)
		}
	}
	return nil
}

func scopeRegistryIDs(scope *domain.MCPScope) []ids.RegistryID {
	seen := make(map[ids.RegistryID]struct{})
	out := make([]ids.RegistryID, 0)
	add := func(id ids.RegistryID) {
		if _, dup := seen[id]; dup {
			return
		}
		seen[id] = struct{}{}
		out = append(out, id)
	}
	for _, id := range scope.RegistryIDs {
		add(id)
	}
	for _, ref := range scope.Tools {
		add(ref.RegistryID)
	}
	return out
}
