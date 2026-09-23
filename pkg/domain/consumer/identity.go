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

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// EndUserHeader is the request header an application uses to name its end user:
// on MCP consumers whose identity source is app it selects the per-user upstream
// connections; on LLM consumers that opt in it is recorded for attribution.
const EndUserHeader = "X-NeuralTrust-End-User"

// Identity is what a consumer declares about who calls it.
//
// It used to declare whether people stood behind the calls (`acts_for_users`)
// and where they came from (`source`). Both are gone: who a request runs as is
// a property of the request, not of the configuration. A verified person is
// whoever their token says; a machine credential that names an end user acts
// for that person; one that names nobody acts as the application. The gateway
// reads that per request (`EndUserFromRequest`) instead of being told in
// advance — which is what stopped an application from doing both, and made an
// admin answer a question about callers it had not met yet.
//
// The struct stays because a consumer may still declare things about its
// callers later, and because rows persist it.
type Identity struct{}

// Normalize is a no-op: nothing is declared here any more.
func (i *Identity) Normalize(t Type) { _ = t }

// Validate is a no-op for the same reason.
func (i Identity) Validate(t Type) error { _ = t; return nil }

// WantsSignIn reports whether the consumer is entered by people signing in and
// holds no credential of its own, which is the only case the built-in identity
// provider may rescue. That is the MCP Store, which is that identity by
// construction and carries no auth to attach one to.
//
// Every other consumer says how it is entered by what is attached to it: an api
// key, a certificate, an identity provider. A consumer with nothing attached is
// entered by nobody — failing closed is the point, because the alternative is
// that revoking the last credential opens a consumer up instead of locking it
// down.
//
// A nil consumer reports false so callers that read this as "may broker a
// login" fail closed.
func (c *Consumer) WantsSignIn() bool {
	return IsStoreConsumer(c)
}

// MaxEndUserLength bounds the opaque end-user id an application may send.
const MaxEndUserLength = 256

// appSubjectPrefix namespaces an application and the end users it names, so
// neither can collide with a platform user's token subject. The reservation is
// enforced where a token becomes a principal (identity.ReservedSubject); this
// is the other half, the minting.
const appSubjectPrefix = identity.AppSubjectPrefix

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
	return AppSubject(consumerID) + ":" + strings.TrimSpace(endUser)
}

// AppSubject is the principal subject the gateway keys an application's own
// upstream accounts by: the consumer itself, namespaced the same way the end
// users it names are (app:<consumer_id>:<end_user>).
//
// The credential a caller presents — an api key, a client certificate, a
// client-credentials token — proves "I am this application"; it is not the
// identity. It cannot be: consumer_auth is a many-to-many table, so one api
// key can serve several consumers, and a key's name is editable and not
// unique per gateway. Keying by the consumer is what makes the account belong
// to the application: rotating, renaming, adding or removing a credential
// never touches a linked account, two credentials of one application share
// the account by design, and two applications never cross.
func AppSubject(consumerID ids.ConsumerID) string {
	return appSubjectPrefix + consumerID.String()
}
