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

package middleware

import (
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/gofiber/fiber/v2"
)

// AdminIdentityKind distinguishes who is calling the admin API. Authorization
// rules differ per kind, so the decision is made once at authentication time
// instead of being re-derived from claim absence further down the stack.
type AdminIdentityKind string

const (
	// AdminIdentityHuman is a tenant-scoped console user. Its authorization is
	// the tenant that owns the gateway.
	AdminIdentityHuman AdminIdentityKind = "human"
	// AdminIdentityService is a machine-to-machine credential bound to a single
	// gateway and a fixed scope set.
	AdminIdentityService AdminIdentityKind = "service"
	// AdminIdentityPlatform is NeuralTrust itself, provisioning across tenants.
	AdminIdentityPlatform AdminIdentityKind = "platform"
)

// AdminIdentity is the authenticated caller of the admin API.
type AdminIdentity struct {
	Kind      AdminIdentityKind
	TenantID  string
	GatewayID string
	Subject   string
	Email     string
	Scopes    []string
}

// IsService reports whether the caller is a machine-to-machine credential.
func (i AdminIdentity) IsService() bool {
	return i.Kind == AdminIdentityService
}

// HasScope reports whether the identity carries the given scope. Non-service
// identities are user-driven and already authorized by the console, so they are
// not scope-restricted here.
func (i AdminIdentity) HasScope(scope string) bool {
	if !i.IsService() {
		return true
	}
	for _, granted := range i.Scopes {
		if granted == scope {
			return true
		}
	}
	return false
}

// StoreAdminIdentity publishes the identity for downstream middleware and
// handlers. The legacy tenant/user locals stay populated so existing handlers
// keep working unchanged.
func StoreAdminIdentity(c *fiber.Ctx, identity AdminIdentity) {
	c.Locals(string(infracontext.AdminIdentityContextKey), identity)
	if identity.TenantID != "" {
		c.Locals(string(infracontext.TenantIDContextKey), identity.TenantID)
	}
	if identity.Subject != "" {
		c.Locals(string(infracontext.UserIDContextKey), identity.Subject)
	}
	if identity.Email != "" {
		c.Locals(string(infracontext.UserEmailContextKey), identity.Email)
	}
}

// AdminIdentityFromContext returns the identity stamped by the admin auth
// middleware. The zero value with an empty kind means the route was reached
// without admin authentication.
func AdminIdentityFromContext(c *fiber.Ctx) AdminIdentity {
	if identity, ok := c.Locals(string(infracontext.AdminIdentityContextKey)).(AdminIdentity); ok {
		return identity
	}
	return AdminIdentity{}
}
