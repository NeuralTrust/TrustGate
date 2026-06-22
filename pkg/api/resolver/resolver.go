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

package resolver

import (
	"errors"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

const HeaderAPIKey = "X-AG-API-Key" // #nosec G101 -- HTTP header name, not a credential

var (
	ErrUnauthenticated = errors.New("unauthenticated")
	ErrForbidden       = errors.New("forbidden")
)

type IdentityResolver interface {
	Resolve(c *fiber.Ctx, gw *gatewaydomain.Gateway, rc *appconsumer.RoutableConsumer) (*appauth.AuthContext, error)
}

func hasAttachedAuthType(rc *appconsumer.RoutableConsumer, authType authdomain.Type) bool {
	if rc == nil {
		return false
	}
	for _, a := range rc.Auths {
		if a != nil && a.Enabled && a.Type == authType {
			return true
		}
	}
	return false
}
