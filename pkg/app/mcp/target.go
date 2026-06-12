package mcp

import (
	"context"
	"fmt"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

// target builds the upstream connection target: static config (none/static
// modes, headers, session pin key) plus the per-principal credential for the
// passthrough/exchange/forwarded modes via the resolver.
func (c *composer) target(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) (Target, error) {
	t := targetFor(ctx, rc, reg)
	if c.creds != nil {
		if err := c.creds.Apply(ctx, rc, reg, &t); err != nil {
			return Target{}, err
		}
	}
	return t, nil
}

// targetFor builds the upstream connection target, applying the registry's
// downstream auth config (none/static) and the session pin key. Per-user
// downstream modes get a per-principal pin so sessions never cross users.
func targetFor(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) Target {
	t := StaticTarget(reg)
	if rc != nil && rc.Consumer != nil {
		t.PinKey = fmt.Sprintf("%s:%s:%s", rc.Consumer.GatewayID, rc.Consumer.ID, reg.ID)
		if perPrincipalAuth(reg) {
			if p := identity.PrincipalFromContext(ctx); p != nil {
				t.PinKey += ":" + p.Subject
			}
		}
	}
	return t
}

func perPrincipalAuth(reg *registrydomain.Registry) bool {
	if reg.MCPTarget == nil || reg.MCPTarget.Auth == nil {
		return false
	}
	switch reg.MCPTarget.Auth.Mode {
	case registrydomain.MCPAuthModePassthrough, registrydomain.MCPAuthModeExchange, registrydomain.MCPAuthModeForwarded:
		return true
	}
	return false
}

// StaticTarget builds the raw connection target for an MCP registry (no
// session pinning). Used by the composer and by admin tool introspection.
func StaticTarget(reg *registrydomain.Registry) Target {
	t := reg.MCPTarget
	headers := make(map[string]string, len(t.Headers)+1)
	for k, v := range t.Headers {
		headers[k] = v
	}
	if t.Auth != nil && t.Auth.Mode == registrydomain.MCPAuthModeStatic {
		headers[t.Auth.Header] = t.Auth.Value
	}
	return Target{URL: t.URL, Headers: headers}
}
