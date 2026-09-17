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
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// MCPToolRef names one upstream tool by its registry and native tool name.
type MCPToolRef struct {
	RegistryID ids.RegistryID `json:"registry_id"`
	Tool       string         `json:"tool"`
}

// MCPScope narrows a policy to MCP destinations and principals. A nil scope
// applies to every tools/call of the consumer; a present scope with no entries
// matches nothing. Destination and principal combine with AND inside one
// scope; an empty dimension accepts any value.
type MCPScope struct {
	RegistryIDs  []ids.RegistryID `json:"registry_ids,omitempty"`
	Tools        []MCPToolRef     `json:"tools,omitempty"`
	Users        []string         `json:"users,omitempty"`
	Groups       []string         `json:"groups,omitempty"`
	ExceptUsers  []string         `json:"except_users,omitempty"`
	ExceptGroups []string         `json:"except_groups,omitempty"`
}

// MCPTarget is the resolved destination of a tools/call: the owning registry
// and the native tool name, never the exposed one.
type MCPTarget struct {
	RegistryID ids.RegistryID
	Tool       string
}

// MCPCaller is the principal view the scope matcher reads. Email is expected
// in lowercase; a caller with no Subject, Email or Groups has no identity and
// never matches users or groups nor falls in an exception.
type MCPCaller struct {
	Subject string
	Email   string
	Groups  []string
}

// SkipReason says which dimension of a scope rejected a call.
type SkipReason string

const (
	// SkipDestination reports that the registry or tool is outside the scope.
	SkipDestination SkipReason = "destination"
	// SkipPrincipal reports that the caller is not in users or groups.
	SkipPrincipal SkipReason = "principal"
	// SkipExcept reports that the caller is excluded by except_users or except_groups.
	SkipExcept SkipReason = "except"
)

// IsEmpty reports whether the scope is present but names nothing.
func (s *MCPScope) IsEmpty() bool {
	return s != nil && !s.HasDestination() && !s.HasPrincipal()
}

// HasDestination reports whether the scope narrows by registry or tool.
func (s *MCPScope) HasDestination() bool {
	return s != nil && (len(s.RegistryIDs) > 0 || len(s.Tools) > 0)
}

// HasPrincipal reports whether the scope narrows by user or group, including
// exceptions.
func (s *MCPScope) HasPrincipal() bool {
	return s != nil && (len(s.Users) > 0 || len(s.Groups) > 0 ||
		len(s.ExceptUsers) > 0 || len(s.ExceptGroups) > 0)
}

// Specificity ranks the scope for tie-breaks at equal priority: destination
// rank (tools=2, registry=1, none=0) doubled, plus one when it narrows by
// principal. A nil scope ranks 0.
func (s *MCPScope) Specificity() uint8 {
	if s == nil {
		return 0
	}
	var rank uint8
	switch {
	case len(s.Tools) > 0:
		rank = 2
	case len(s.RegistryIDs) > 0:
		rank = 1
	}
	rank *= 2
	if s.HasPrincipal() {
		rank++
	}
	return rank
}

// MatchesTarget reports whether the target's registry is in RegistryIDs or its
// (registry, native tool) pair is in Tools. A scope without destination accepts
// any target.
func (s *MCPScope) MatchesTarget(t MCPTarget) bool {
	if !s.HasDestination() {
		return true
	}
	for _, id := range s.RegistryIDs {
		if id == t.RegistryID {
			return true
		}
	}
	for _, ref := range s.Tools {
		if ref.RegistryID == t.RegistryID && ref.Tool == t.Tool {
			return true
		}
	}
	return false
}

// MatchesCaller reports whether the caller is selected by Users or Groups and
// not excluded by ExceptUsers or ExceptGroups. A scope without principal
// accepts any caller; a caller without identity is never selected by Users or
// Groups and never excluded.
func (s *MCPScope) MatchesCaller(c MCPCaller) (bool, SkipReason) {
	if !s.HasPrincipal() {
		return true, ""
	}
	subject := strings.TrimSpace(c.Subject)
	email := strings.ToLower(strings.TrimSpace(c.Email))
	hasIdentity := subject != "" || email != "" || len(c.Groups) > 0
	if len(s.Users) > 0 || len(s.Groups) > 0 {
		if !hasIdentity {
			return false, SkipPrincipal
		}
		if !containsUser(s.Users, subject, email) && !intersectsGroups(s.Groups, c.Groups) {
			return false, SkipPrincipal
		}
	}
	if hasIdentity && (containsUser(s.ExceptUsers, subject, email) || intersectsGroups(s.ExceptGroups, c.Groups)) {
		return false, SkipExcept
	}
	return true, ""
}

// Matches reports whether the policy applies to a tools/call. A nil scope
// always applies; a present scope with no entries never does. Destination and
// principal must both match, then the exceptions are applied.
func (s *MCPScope) Matches(t MCPTarget, c MCPCaller) (bool, SkipReason) {
	if s == nil {
		return true, ""
	}
	if s.IsEmpty() || !s.MatchesTarget(t) {
		return false, SkipDestination
	}
	return s.MatchesCaller(c)
}

// Validate checks the scope's structure and wraps every failure in
// ErrInvalidMCPScope: nil registry ids, blank tools, users or groups,
// duplicates, and a registry named both in RegistryIDs and in Tools. An empty
// scope is valid, so a policy pruned to {} can still be saved.
func (s *MCPScope) Validate() error {
	if s == nil {
		return nil
	}
	registries := make(map[ids.RegistryID]struct{}, len(s.RegistryIDs))
	for _, id := range s.RegistryIDs {
		if id.IsNil() {
			return fmt.Errorf("%w: nil registry_id", ErrInvalidMCPScope)
		}
		if _, dup := registries[id]; dup {
			return fmt.Errorf("%w: duplicate registry_id %s", ErrInvalidMCPScope, id)
		}
		registries[id] = struct{}{}
	}
	tools := make(map[MCPToolRef]struct{}, len(s.Tools))
	for _, ref := range s.Tools {
		if ref.RegistryID.IsNil() {
			return fmt.Errorf("%w: nil registry_id in tools", ErrInvalidMCPScope)
		}
		tool := strings.TrimSpace(ref.Tool)
		if tool == "" {
			return fmt.Errorf("%w: empty tool for registry %s", ErrInvalidMCPScope, ref.RegistryID)
		}
		if _, both := registries[ref.RegistryID]; both {
			return fmt.Errorf("%w: registry %s is in both registry_ids and tools", ErrInvalidMCPScope, ref.RegistryID)
		}
		key := MCPToolRef{RegistryID: ref.RegistryID, Tool: tool}
		if _, dup := tools[key]; dup {
			return fmt.Errorf("%w: duplicate tool %s on registry %s", ErrInvalidMCPScope, tool, ref.RegistryID)
		}
		tools[key] = struct{}{}
	}
	for _, list := range []struct {
		field  string
		values []string
	}{
		{"users", s.Users},
		{"groups", s.Groups},
		{"except_users", s.ExceptUsers},
		{"except_groups", s.ExceptGroups},
	} {
		if err := validateSubjects(list.field, list.values); err != nil {
			return err
		}
	}
	return nil
}

// Normalize trims every tool, user and group entry and lowercases the entries
// of Users and ExceptUsers that look like emails. Subjects keep their case.
func (s *MCPScope) Normalize() {
	if s == nil {
		return
	}
	for i := range s.Tools {
		s.Tools[i].Tool = strings.TrimSpace(s.Tools[i].Tool)
	}
	normalizeUsers(s.Users)
	normalizeUsers(s.ExceptUsers)
	trimAll(s.Groups)
	trimAll(s.ExceptGroups)
}

// PruneRegistry removes every reference to registryID from the scope's
// RegistryIDs and Tools and reports whether anything changed. A scope whose
// destination is left empty is reset to {} rather than nil, so the policy goes
// dormant instead of widening to the whole consumer.
func (p *Policy) PruneRegistry(registryID ids.RegistryID) bool {
	if p == nil || p.MCPScope == nil || registryID.IsNil() {
		return false
	}
	scope := p.MCPScope
	registries := make([]ids.RegistryID, 0, len(scope.RegistryIDs))
	for _, id := range scope.RegistryIDs {
		if id != registryID {
			registries = append(registries, id)
		}
	}
	tools := make([]MCPToolRef, 0, len(scope.Tools))
	for _, ref := range scope.Tools {
		if ref.RegistryID != registryID {
			tools = append(tools, ref)
		}
	}
	if len(registries) == len(scope.RegistryIDs) && len(tools) == len(scope.Tools) {
		return false
	}
	if len(registries) == 0 && len(tools) == 0 {
		p.MCPScope = &MCPScope{}
		return true
	}
	scope.RegistryIDs = nilIfEmpty(registries)
	scope.Tools = nilIfEmpty(tools)
	return true
}

func containsUser(users []string, subject, email string) bool {
	for _, u := range users {
		if (subject != "" && u == subject) || (email != "" && u == email) {
			return true
		}
	}
	return false
}

func intersectsGroups(scoped, caller []string) bool {
	if len(scoped) == 0 || len(caller) == 0 {
		return false
	}
	for _, grp := range caller {
		grp = strings.TrimSpace(grp)
		if grp == "" {
			continue
		}
		for _, want := range scoped {
			if want == grp {
				return true
			}
		}
	}
	return false
}

func validateSubjects(field string, values []string) error {
	seen := make(map[string]struct{}, len(values))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			return fmt.Errorf("%w: empty entry in %s", ErrInvalidMCPScope, field)
		}
		if _, dup := seen[v]; dup {
			return fmt.Errorf("%w: duplicate entry %q in %s", ErrInvalidMCPScope, v, field)
		}
		seen[v] = struct{}{}
	}
	return nil
}

func normalizeUsers(users []string) {
	for i, u := range users {
		u = strings.TrimSpace(u)
		if strings.Contains(u, "@") {
			u = strings.ToLower(u)
		}
		users[i] = u
	}
}

func trimAll(values []string) {
	for i, v := range values {
		values[i] = strings.TrimSpace(v)
	}
}

func nilIfEmpty[T any](in []T) []T {
	if len(in) == 0 {
		return nil
	}
	return in
}
