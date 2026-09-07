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

package consumer

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// IdentitySource says where the end users of an acts-for-users consumer come
// from.
type IdentitySource string

const (
	// IdentitySourcePlatform: the people using the application sign in
	// themselves (the NeuralTrust IdP or the customer's IdP). Their subject and
	// groups come from the token, so Access rules govern which of the
	// consumer's servers each of them may reach, and each connects their own
	// upstream accounts.
	IdentitySourcePlatform IdentitySource = "platform"
	// IdentitySourceApp: the application authenticates itself (API key) and
	// names its end user on every request through the end-user header. The
	// gateway keeps per-user upstream connections under a namespaced subject;
	// Access rules do not apply because the application owns its user
	// directory.
	IdentitySourceApp IdentitySource = "app"
)

// IsValid reports whether s is a known identity source.
func (s IdentitySource) IsValid() bool {
	return s == IdentitySourcePlatform || s == IdentitySourceApp
}

// EndUserHeader is the request header an application uses to name its end user:
// on MCP consumers whose identity source is app it selects the per-user upstream
// connections; on LLM consumers that opt in it is recorded for attribution.
const EndUserHeader = "X-NeuralTrust-End-User"

// Identity describes who a consumer acts for. Every consumer is an application;
// what changes is whether a person stands behind each request and how the
// gateway learns who that person is. It never selects a registry or a model:
// routing is the consumer's own configuration.
type Identity struct {
	// ActsForUsers turns on per-user behaviour on an MCP consumer: per-user
	// upstream connections and, with the platform source, Access rules over the
	// consumer's servers. Off, the consumer acts as the application itself.
	ActsForUsers bool `json:"acts_for_users"`
	// Source is how the end user is known (platform or app). Only meaningful
	// when ActsForUsers is on; defaults to platform.
	Source IdentitySource `json:"source,omitempty"`
	// EndUserHeader lets an LLM consumer forward an opaque end-user id for
	// attribution in traces, audit and rate limiting.
	EndUserHeader bool `json:"end_user_header,omitempty"`
}

// Normalize fills the defaults for a consumer of the given type: the platform
// source when acting for users without one, and no source otherwise.
func (i *Identity) Normalize(t Type) {
	if i == nil {
		return
	}
	i.Source = IdentitySource(strings.ToLower(strings.TrimSpace(string(i.Source))))
	if !i.ActsForUsers {
		i.Source = ""
		return
	}
	if i.Source == "" {
		i.Source = IdentitySourcePlatform
	}
	_ = t
}

// Validate checks the identity against the consumer type.
func (i Identity) Validate(t Type) error {
	if i.ActsForUsers {
		if t != TypeMCP {
			return fmt.Errorf("%w: acts_for_users is only valid for MCP consumers", ErrInvalidIdentity)
		}
		if !i.Source.IsValid() {
			return fmt.Errorf("%w: unknown source %q", ErrInvalidIdentity, i.Source)
		}
	} else if i.Source != "" {
		return fmt.Errorf("%w: source requires acts_for_users", ErrInvalidIdentity)
	}
	if i.EndUserHeader && t != TypeLLM {
		return fmt.Errorf("%w: end_user_header is only valid for LLM consumers", ErrInvalidIdentity)
	}
	return nil
}

// PlatformUsers reports whether the consumer acts for people who sign in
// themselves, which is when Access rules scope its servers per principal.
func (i Identity) PlatformUsers() bool {
	return i.ActsForUsers && i.Source == IdentitySourcePlatform
}

// AppUsers reports whether the consumer acts for end users the application
// names through the end-user header.
func (i Identity) AppUsers() bool {
	return i.ActsForUsers && i.Source == IdentitySourceApp
}

// ActsForUsers reports whether the consumer acts on behalf of end users.
func (c *Consumer) ActsForUsers() bool {
	return c != nil && c.Identity.ActsForUsers
}

// MaxEndUserLength bounds the opaque end-user id an application may send.
const MaxEndUserLength = 256

// endUserSubjectPrefix namespaces app-identified end users so their vault
// subject can never collide with a platform user's token subject.
const endUserSubjectPrefix = "app:"

// ValidateEndUser checks an end-user id from the end-user header: present,
// bounded and printable. The gateway never interprets it.
func ValidateEndUser(id string) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("%w: %s header is required", ErrInvalidEndUser, EndUserHeader)
	}
	if len(id) > MaxEndUserLength {
		return fmt.Errorf("%w: %s header longer than %d characters", ErrInvalidEndUser, EndUserHeader, MaxEndUserLength)
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return fmt.Errorf("%w: %s header contains control characters", ErrInvalidEndUser, EndUserHeader)
		}
	}
	return nil
}

// EndUserSubject is the principal subject the gateway keys per-user upstream
// connections by for an end user an application named: namespaced by the
// consumer so two applications naming "user_123" never share a connection.
func EndUserSubject(consumerID ids.ConsumerID, endUser string) string {
	return endUserSubjectPrefix + consumerID.String() + ":" + strings.TrimSpace(endUser)
}
