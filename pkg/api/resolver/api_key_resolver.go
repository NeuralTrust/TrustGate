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
	appauth "github.com/NeuralTrust/AgentGateway/pkg/app/auth"
	appconsumer "github.com/NeuralTrust/AgentGateway/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/AgentGateway/pkg/domain/gateway"
	"github.com/gofiber/fiber/v2"
)

type APIKeyIdentityResolver struct{}

func NewAPIKeyIdentityResolver() *APIKeyIdentityResolver {
	return &APIKeyIdentityResolver{}
}

func (r *APIKeyIdentityResolver) Resolve(
	c *fiber.Ctx,
	gw *gatewaydomain.Gateway,
	rc *appconsumer.RoutableConsumer,
) (*appauth.AuthContext, error) {
	rawKey := c.Get(HeaderAPIKey)
	if rawKey == "" {
		return nil, ErrUnauthenticated
	}
	if rc == nil || rc.Consumer == nil || rc.Consumer.RoutingMode == consumerdomain.RoutingModeRoleBased {
		return nil, ErrForbidden
	}
	hash := authdomain.HashAPIKey(rawKey)
	for _, a := range rc.Auths {
		if a == nil || !a.Enabled || a.Type != authdomain.TypeAPIKey || a.KeyHash != hash {
			continue
		}
		return &appauth.AuthContext{
			Method:      appauth.MethodAPIKey,
			GatewayID:   gw.ID,
			GatewaySlug: gw.Slug,
			ConsumerID:  rc.Consumer.ID,
			AuthID:      a.ID,
		}, nil
	}
	if hasAttachedAuthType(rc, authdomain.TypeAPIKey) {
		return nil, ErrUnauthenticated
	}
	return nil, ErrForbidden
}
