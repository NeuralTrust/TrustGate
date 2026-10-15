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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// customStoreCodePrefix marks the MCP Store code of a custom server: one added
// by URL, which has no catalog code of its own.
const customStoreCodePrefix = "custom:"

// CustomStoreCode is the MCP Store code of the custom server registry id: the
// key its grants, installs and requests carry in place of a catalog code.
func CustomStoreCode(id ids.RegistryID) string {
	return customStoreCodePrefix + id.String()
}

// ParseCustomStoreCode returns the registry a custom server's Store code names,
// and false for any other code (a catalog code included).
func ParseCustomStoreCode(code string) (ids.RegistryID, bool) {
	raw, ok := strings.CutPrefix(strings.TrimSpace(code), customStoreCodePrefix)
	if !ok {
		return ids.RegistryID{}, false
	}
	id, err := ids.Parse[ids.RegistryKind](raw)
	if err != nil || id.IsNil() {
		return ids.RegistryID{}, false
	}
	return id, true
}

// StoreCode is the code the MCP Store knows an MCP registry by: its catalog
// code, or for a custom server the code derived from its id. Empty for a
// registry that is not an MCP server.
func StoreCode(reg *Registry) string {
	if reg == nil || reg.MCPTarget == nil {
		return ""
	}
	if code := strings.TrimSpace(reg.MCPTarget.Code); code != "" {
		return code
	}
	return CustomStoreCode(reg.ID)
}
