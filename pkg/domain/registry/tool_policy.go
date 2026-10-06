// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package registry

import (
	"fmt"
	"strings"
)

// ToolPolicy decides how an MCP registry's tools reach consumers.
type ToolPolicy string

const (
	// ToolPolicyAuto exposes whatever the upstream server lists. It is the
	// default and the behaviour every registry had before pinning existed.
	ToolPolicyAuto ToolPolicy = "auto"
	// ToolPolicyPinned exposes only the tools an admin approved, by name and
	// definition fingerprint.
	ToolPolicyPinned ToolPolicy = "pinned"
)

// Validate rejects anything that is not a known policy. The empty value is not
// valid here: callers default it with Normalize first.
func (p ToolPolicy) Validate() error {
	switch p {
	case ToolPolicyAuto, ToolPolicyPinned:
		return nil
	default:
		return fmt.Errorf("%w: unsupported tool_policy %q", ErrInvalidToolPolicy, string(p))
	}
}

// Normalize trims and lowercases the policy and maps the empty value to auto.
func (p ToolPolicy) Normalize() ToolPolicy {
	n := ToolPolicy(strings.ToLower(strings.TrimSpace(string(p))))
	if n == "" {
		return ToolPolicyAuto
	}
	return n
}

// IsPinned reports whether the policy filters tools through the approved set.
func (p ToolPolicy) IsPinned() bool { return p == ToolPolicyPinned }
