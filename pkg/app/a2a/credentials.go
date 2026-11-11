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

package a2a

import (
	"context"
	"net/http"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// ReasonAuthUnsupported is the -32092 reason of a registry whose auth mode the
// agent plane cannot send.
const ReasonAuthUnsupported = "auth_unsupported"

// IdentityTrace is how a call identified itself to the agent.
type IdentityTrace struct {
	Mode        string
	SubjectKind string
}

// Credentials builds the credential an A2A registry's auth mode sends.
type Credentials struct{}

// NewCredentials builds the agent plane's credentials.
func NewCredentials() *Credentials {
	return &Credentials{}
}

// For returns the headers that carry the credential of a call by p to reg.
func (c *Credentials) For(_ context.Context, _ *appconsumer.RoutableConsumer, reg *registrydomain.Registry, _ *identity.Principal) (http.Header, IdentityTrace, *RPCError) {
	auth := reg.A2ATarget.Auth
	header := http.Header{}
	switch auth.Mode {
	case "", registrydomain.MCPAuthModeNone:
		return header, IdentityTrace{Mode: string(registrydomain.MCPAuthModeNone)}, nil
	case registrydomain.MCPAuthModeStatic:
		header.Set(auth.Header, auth.Value)
		return header, IdentityTrace{Mode: string(auth.Mode)}, nil
	}
	return nil, IdentityTrace{}, GatewayFailure(ReasonAuthUnsupported)
}
