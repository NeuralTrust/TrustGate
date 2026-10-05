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

package gateway

import (
	"context"
	"errors"
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
)

var ErrInvalidTrafficLabelingRegistry = fmt.Errorf("traffic_labeling.registry_id: %w", commonerrors.ErrValidation)

// RegistryFinder resolves the registry a gateway's traffic labeling runs on.
type RegistryFinder interface {
	FindByID(ctx context.Context, id ids.RegistryID) (*registrydomain.Registry, error)
}

// validateTrafficLabelingRegistry checks that an enabled config points at an
// LLM registry of the gateway that holds its own credentials: the worker has
// no client key to forward.
func validateTrafficLabelingRegistry(ctx context.Context, registries RegistryFinder, gatewayID ids.GatewayID, cfg *trafficlabel.Config) error {
	if cfg == nil || !cfg.Enabled {
		return nil
	}
	id, ok := cfg.Registry()
	if !ok {
		return fmt.Errorf("%w: a valid registry id is required", ErrInvalidTrafficLabelingRegistry)
	}
	if registries == nil {
		return fmt.Errorf("traffic_labeling: registry lookup is not available")
	}
	reg, err := registries.FindByID(ctx, id)
	if errors.Is(err, commonerrors.ErrNotFound) || (err == nil && reg == nil) {
		return fmt.Errorf("%w: registry %s does not exist", ErrInvalidTrafficLabelingRegistry, id)
	}
	if err != nil {
		return fmt.Errorf("traffic_labeling: find registry: %w", err)
	}
	if reg.GatewayID != gatewayID {
		return fmt.Errorf("%w: registry %s does not belong to this gateway", ErrInvalidTrafficLabelingRegistry, id)
	}
	if reg.Type != registrydomain.TypeLLM || reg.LLMTarget == nil {
		return fmt.Errorf("%w: registry %s is not an LLM registry", ErrInvalidTrafficLabelingRegistry, id)
	}
	auth := reg.Auth()
	if auth == nil || auth.Type == registrydomain.AuthTypePassthrough || auth.Type == registrydomain.AuthTypeOAuth2 {
		return fmt.Errorf("%w: registry %s has no stored credentials; client pass-through auth cannot be used for labeling", ErrInvalidTrafficLabelingRegistry, id)
	}
	return nil
}
