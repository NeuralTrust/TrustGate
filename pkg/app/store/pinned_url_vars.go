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

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func boundTarget(reg *registrydomain.Registry) *registrydomain.MCPTarget {
	if reg == nil {
		return nil
	}
	return reg.MCPTarget
}

func unpinnedURLVariables(vars []registrydomain.MCPURLVariable, bound *registrydomain.MCPTarget) []registrydomain.MCPURLVariable {
	if len(vars) == 0 {
		return nil
	}
	out := make([]registrydomain.MCPURLVariable, 0, len(vars))
	for _, v := range vars {
		if !bound.PinsURLVariable(v.Name) {
			out = append(out, v)
		}
	}
	return out
}

// ServingTarget is the target of the instance that serves an install of code:
// the one registryID names, else the code's canonical (oldest) instance. Nil
// when the gateway holds none yet, so a caller treats every catalog variable as
// per-user. The hosted configure form uses it to leave out the variables that
// instance's URL already fixes, as the installer does.
func ServingTarget(
	ctx context.Context,
	lister RegistryLister,
	gatewayID ids.GatewayID,
	code string,
	registryID ids.RegistryID,
) (*registrydomain.MCPTarget, error) {
	if lister == nil {
		return nil, nil
	}
	regs, err := findRegistriesByCode(ctx, lister, gatewayID, code)
	if err != nil {
		return nil, err
	}
	return boundTarget(servingRegistry(regs, registryID)), nil
}

func servingRegistry(regs []*registrydomain.Registry, registryID ids.RegistryID) *registrydomain.Registry {
	if !registryID.IsNil() {
		return pickRegistry(regs, registryID)
	}
	if len(regs) == 0 {
		return nil
	}
	return regs[0]
}
