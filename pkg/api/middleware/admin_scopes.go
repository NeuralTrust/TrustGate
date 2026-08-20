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
	"github.com/gofiber/fiber/v2"
)

// AdminResource names a gateway-scoped collection for scope checks. Routes
// declare their resource when they are mounted rather than having it parsed out
// of the request path, so a new route cannot silently inherit a weaker scope.
type AdminResource string

const (
	ResourceGateways   AdminResource = "gateways"
	ResourceRegistries AdminResource = "registries"
	ResourcePolicies   AdminResource = "policies"
	ResourceConsumers  AdminResource = "consumers"
	ResourceRoles      AdminResource = "roles"
	ResourceAuths      AdminResource = "auths"
)

const (
	scopeReadSuffix  = ":read"
	scopeWriteSuffix = ":write"
)

// RequiredScope maps a resource and HTTP method to the scope a service
// credential must carry. Everything that is not a safe read is treated as a
// write, so a new mutating route defaults to the stricter scope.
func RequiredScope(resource AdminResource, method string) string {
	switch method {
	case fiber.MethodGet, fiber.MethodHead, fiber.MethodOptions:
		return string(resource) + scopeReadSuffix
	default:
		return string(resource) + scopeWriteSuffix
	}
}
