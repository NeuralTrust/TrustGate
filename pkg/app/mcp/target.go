package mcp

import (
	"context"
	"fmt"

	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/registry"
)

func (c *composer) target(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) (Target, error) {
	t := targetFor(ctx, rc, reg)
	if c.creds != nil {
		if err := c.creds.Apply(ctx, rc, reg, &t); err != nil {
			return Target{}, err
		}
	}
	return t, nil
}

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
