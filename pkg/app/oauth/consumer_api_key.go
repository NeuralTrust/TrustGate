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

package oauth

import (
	"errors"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// ErrAPIKeyConnectUnauthorized is the one refusal every api-key-authenticated
// connections call gives: unknown slug, unknown key, a key that is not this
// consumer's. They are indistinguishable on purpose — the caller is not
// authenticated yet, and a talkative answer enumerates a gateway.
var ErrAPIKeyConnectUnauthorized = errors.New("oauth api-key connect: unauthorized")

// validMCPConsumer reports whether a resolved slug is an active MCP consumer of
// this gateway.
func validMCPConsumer(target *appconsumer.RoutableConsumer, gatewayID ids.GatewayID) bool {
	return target != nil &&
		target.Consumer != nil &&
		target.Consumer.Active &&
		target.Consumer.Type == consumerdomain.TypeMCP &&
		target.Consumer.GatewayID == gatewayID
}

// validAPIKeyAuth reports whether the presented key is an enabled api key of
// this gateway that the consumer actually holds.
func validAPIKeyAuth(auth *authdomain.Auth, consumer *consumerdomain.Consumer, gatewayID ids.GatewayID) bool {
	if auth == nil ||
		!auth.Enabled ||
		auth.Type != authdomain.TypeAPIKey ||
		auth.GatewayID != gatewayID {
		return false
	}
	for _, authID := range consumer.AuthIDs {
		if authID == auth.ID {
			return true
		}
	}
	return false
}
