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

package consumer

import (
	"fmt"

	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// ScopeRefusal reports why a policy's mcp_scope cannot gate traffic on this
// consumer's plane, or nil when it can.
//
// It refuses the scopes that would reach a non-MCP consumer and do nothing
// there. It is the write-side half of the predicate the config load applies
// when it builds the inert plan; the two have to agree, or an operator gets a
// 204 and a policy that never runs.
//
// A scope narrowing by group alone is allowed, provided the plugin does not
// resolve tool or registry names: outside MCP the group is inert, and a plugin
// that gates by name would then widen from "all but Finance" to "all"
// (RUN-1621, rule 2). The three refusals carry different sentences so an
// operator can act on whichever they hit.
//
// It lives here, rather than inside the attach that first needed it, because
// every path that can put a scope next to a consumer has to apply it. It used
// to be a method on the associator, so attaching was checked and updating the
// scope of an already-attached policy was not — the same end state, reachable
// by going the other way round.
func ScopeRefusal(cons *Consumer, pol *policydomain.Policy, inertSafe bool) error {
	if cons == nil || pol == nil || pol.MCPScope == nil || cons.Type == TypeMCP {
		return nil
	}
	switch {
	case pol.MCPScope.HasDestination():
		return fmt.Errorf("%w: the scope names a registry or a tool, and neither exists outside MCP; consumer %s is of type %s",
			ErrPolicyScopeDoesNotCross, cons.ID, cons.Type)
	case pol.Dormant():
		return fmt.Errorf("%w: the scope is empty and names nothing, so the policy would run nowhere; consumer %s is of type %s",
			ErrPolicyScopeDoesNotCross, cons.ID, cons.Type)
	case !inertSafe:
		return fmt.Errorf("%w: plugin %s has not opted into running where the scope is inert, which a plugin that resolves tool or registry names cannot do; consumer %s is of type %s",
			ErrPolicyScopeDoesNotCross, pol.Slug, cons.ID, cons.Type)
	}
	return nil
}
