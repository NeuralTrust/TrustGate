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
	"cmp"
	"context"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	"github.com/gofiber/fiber/v2"
)

// changeContext is the context a create, update or delete runs in: marked as
// the platform's when NeuralTrust itself asks, which is the only caller a
// managed registry takes changes from.
func changeContext(c *fiber.Ctx) context.Context {
	identity := middleware.AdminIdentityFromContext(c)
	ctx := appsecretstore.WithCaller(c.UserContext(), appsecretstore.Caller{
		MayReference:    identity.HasScope(middleware.ScopeSecretStoresRead),
		AllowUnverified: c.QueryBool("allow_unverified_secret_refs"),
		Actor:           cmp.Or(identity.Email, identity.Subject),
	})
	if identity.Kind == middleware.AdminIdentityPlatform {
		return appregistry.AsPlatform(ctx)
	}
	return ctx
}
