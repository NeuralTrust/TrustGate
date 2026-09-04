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

package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func (c *composer) target(ctx context.Context, rc *appconsumer.RoutableConsumer, reg *registrydomain.Registry) (Target, error) {
	t := targetFor(ctx, rc, reg)
	if err := c.resolveURLVariables(ctx, rc, reg, &t); err != nil {
		return Target{}, err
	}
	if c.creds != nil {
		if err := c.creds.Apply(ctx, rc, reg, &t); err != nil {
			return Target{}, err
		}
	}
	return t, nil
}

// resolveURLVariables substitutes a registry's per-user URL placeholders into the
// dial target from the calling principal's install. It is a no-op for the common
// case (no placeholders). The resolved URL is folded into the session pin key so
// one principal's connection is never reused for another's — the placeholders are
// exactly what makes the upstream per-user — and so a changed value re-pins.
func (c *composer) resolveURLVariables(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	t *Target,
) error {
	if reg.MCPTarget == nil || !reg.MCPTarget.HasURLVariables() {
		return nil
	}
	var values map[string]string
	if c.urlvars != nil {
		v, err := c.urlvars.Resolve(ctx, rc, reg)
		if err != nil {
			return err
		}
		values = v
	}
	resolved, err := registrydomain.ResolveURL(reg.MCPTarget.URL, reg.MCPTarget.URLVariables, values)
	if err != nil {
		return err
	}
	t.URL = resolved
	if t.OpenAPI != nil {
		t.OpenAPI.BaseURL = resolved
	}
	sum := sha256.Sum256([]byte(resolved))
	t.PinKey += ":u:" + hex.EncodeToString(sum[:8])
	return nil
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
	target := Target{
		URL:      t.URL,
		Headers:  headers,
		Revision: reg.ID.String() + ":" + reg.UpdatedAt.UTC().Format("20060102150405.000"),
	}
	if t.Source == registrydomain.MCPSourceOpenAPI && t.OpenAPI != nil {
		target.OpenAPI = &appopenapi.Source{SpecURL: t.OpenAPI.SpecURL, BaseURL: t.URL}
	}
	return target
}
