package mcp

import (
	"context"
	"errors"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	approle "github.com/NeuralTrust/AgentGateway/pkg/app/role"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	identitydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/AgentGateway/pkg/domain/role"
)

var ErrNoRoleAccess = errors.New("mcp: no role grants MCP access for this identity")

//go:generate mockery --name=RoleScoper --dir=. --output=./mocks --filename=role_scoper_mock.go --case=underscore --with-expecter
type RoleScoper interface {
	Scope(ctx context.Context, rc *appconsumer.RoutableConsumer, data *appconsumer.Data) (*appconsumer.RoutableConsumer, error)
}

var _ RoleScoper = (*roleScoper)(nil)

type roleScoper struct {
	idpResolver approle.IDPResolver
}

func NewRoleScoper(idpResolver approle.IDPResolver) RoleScoper {
	return &roleScoper{idpResolver: idpResolver}
}

// Scope returns the consumer view the MCP plane should operate on. Inline
// consumers pass through untouched; role_based consumers get an effective
// view built from the roles granted to the authenticated principal:
// registries are the union of the roles' MCP registries, the toolkit is the
// union of the roles' mcp_policies toolkits (a role binding an MCP registry
// without an explicit toolkit grants it fully), and fail_mode is open only
// when every contributing role declares it open.
func (s *roleScoper) Scope(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	data *appconsumer.Data,
) (*appconsumer.RoutableConsumer, error) {
	if rc == nil || rc.Consumer == nil || rc.Consumer.RoutingMode != consumerdomain.RoutingModeRoleBased {
		return rc, nil
	}
	principal := identitydomain.PrincipalFromContext(ctx)
	if principal == nil || len(principal.Claims) == 0 {
		return nil, ErrNoRoleAccess
	}
	resolved, err := s.idpResolver.ResolveIDPRoles(ctx, data.Roles, principal.Claims)
	if err != nil {
		return nil, err
	}
	matched := matchedRoles(data.Roles, intersectRoleIDs(resolved, rc.Consumer.RoleIDs))
	if len(matched) == 0 {
		return nil, ErrNoRoleAccess
	}
	view := buildRoleView(matched, data)
	if len(view.registries) == 0 {
		return nil, ErrNoRoleAccess
	}
	effectiveConsumer := *rc.Consumer
	effectiveConsumer.MCP = &consumerdomain.MCPPolicy{
		Toolkit:  view.toolkit,
		FailMode: view.failMode,
	}
	effective := *rc
	effective.Consumer = &effectiveConsumer
	effective.Registries = view.registries
	return &effective, nil
}

type roleView struct {
	registries []*registrydomain.Registry
	toolkit    consumerdomain.Toolkit
	failMode   consumerdomain.FailMode
}

func buildRoleView(roles []*roledomain.Role, data *appconsumer.Data) roleView {
	view := roleView{
		toolkit:  make(consumerdomain.Toolkit, 0),
		failMode: consumerdomain.FailModeOpen,
	}
	seenRegistries := make(map[ids.RegistryID]struct{})
	seenEntries := make(map[string]struct{})
	contributing := 0
	for _, role := range roles {
		mcpRegs := roleMCPRegistries(role, data)
		if len(mcpRegs) == 0 {
			continue
		}
		contributing++
		if !roleFailsOpen(role) {
			view.failMode = consumerdomain.FailModeClosed
		}
		for _, reg := range mcpRegs {
			if _, dup := seenRegistries[reg.ID]; !dup {
				seenRegistries[reg.ID] = struct{}{}
				view.registries = append(view.registries, reg)
			}
		}
		for _, entry := range roleToolkitEntries(role, mcpRegs) {
			key := toolkitEntryKey(entry)
			if _, dup := seenEntries[key]; dup {
				continue
			}
			seenEntries[key] = struct{}{}
			view.toolkit = append(view.toolkit, entry)
		}
	}
	if contributing == 0 {
		view.failMode = consumerdomain.FailModeClosed
	}
	return view
}

func roleMCPRegistries(role *roledomain.Role, data *appconsumer.Data) []*registrydomain.Registry {
	var out []*registrydomain.Registry
	for _, id := range role.RegistryIDs {
		reg, ok := data.RegistryByID(id)
		if !ok || !reg.IsMCP() {
			continue
		}
		out = append(out, reg)
	}
	return out
}

func roleToolkitEntries(role *roledomain.Role, mcpRegs []*registrydomain.Registry) []consumerdomain.ToolkitEntry {
	if role.MCPPolicies == nil {
		out := make([]consumerdomain.ToolkitEntry, 0, len(mcpRegs)*3)
		for _, reg := range mcpRegs {
			out = append(out,
				consumerdomain.ToolkitEntry{RegistryID: reg.ID, Tool: consumerdomain.ToolWildcard},
				consumerdomain.ToolkitEntry{RegistryID: reg.ID, Prompt: consumerdomain.ToolWildcard},
				consumerdomain.ToolkitEntry{RegistryID: reg.ID, Resource: consumerdomain.ToolWildcard},
			)
		}
		return out
	}
	allowed := make(map[ids.RegistryID]struct{}, len(mcpRegs))
	for _, reg := range mcpRegs {
		allowed[reg.ID] = struct{}{}
	}
	out := make([]consumerdomain.ToolkitEntry, 0, len(role.MCPPolicies.Toolkit))
	for _, entry := range role.MCPPolicies.Toolkit {
		if _, ok := allowed[entry.RegistryID]; !ok {
			continue
		}
		out = append(out, entry)
	}
	return out
}

func roleFailsOpen(role *roledomain.Role) bool {
	return role.MCPPolicies != nil && role.MCPPolicies.FailMode == consumerdomain.FailModeOpen
}

func toolkitEntryKey(e consumerdomain.ToolkitEntry) string {
	return e.RegistryID.String() + "\x00" + e.Tool + "\x00" + e.Prompt + "\x00" + e.Resource + "\x00" + e.ExposeAs
}

func matchedRoles(roles []*roledomain.Role, roleIDs []ids.RoleID) []*roledomain.Role {
	wanted := make(map[ids.RoleID]struct{}, len(roleIDs))
	for _, id := range roleIDs {
		wanted[id] = struct{}{}
	}
	out := make([]*roledomain.Role, 0, len(roleIDs))
	for _, role := range roles {
		if role == nil {
			continue
		}
		if _, ok := wanted[role.ID]; ok {
			out = append(out, role)
		}
	}
	return out
}

func intersectRoleIDs(resolved, assigned []ids.RoleID) []ids.RoleID {
	assignedSet := make(map[ids.RoleID]struct{}, len(assigned))
	for _, id := range assigned {
		assignedSet[id] = struct{}{}
	}
	out := make([]ids.RoleID, 0, len(resolved))
	for _, id := range resolved {
		if _, ok := assignedSet[id]; ok {
			out = append(out, id)
		}
	}
	return out
}
