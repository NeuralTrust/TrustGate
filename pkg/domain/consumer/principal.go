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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
)

// EndUserPrincipal is the principal a request runs as when a machine
// credential of cons names endUser.
func EndUserPrincipal(cons *Consumer, app *identity.Principal, endUser string) *identity.Principal {
	endUser = strings.TrimSpace(endUser)
	p := &identity.Principal{
		Subject: EndUserSubject(cons.ID, endUser),
		Method:  identity.MethodAPIKey,
		Claims: map[string]any{
			"end_user":    endUser,
			"consumer_id": cons.ID.String(),
		},
	}
	if app != nil {
		if app.Method != "" {
			p.Method = app.Method
		}
		if app.Subject != "" {
			p.Claims["app_subject"] = app.Subject
		}
	}
	return p
}

// AppPrincipal is the principal a request runs as on a consumer that acts as
// the application itself and was entered with a credential the application
// holds: the consumer-namespaced subject its upstream accounts hang off. The
// credential's own subject stays in the claims, so an audit trail still names
// the api key or the certificate that was used.
//
// The swap happens here, after the auth binding has been applied to the real
// caller, because only the request path knows which consumer is being entered:
// an api key is a many-to-many row, so the credential alone cannot say whose
// application this is.
//
// It is deliberately limited to an api key or a client certificate — a shared
// credential, where callers already share whatever it opens. A bearer token
// keeps its own subject: on a consumer that admits tokens from an external IdP
// the token may well be one person's, and collapsing those onto one subject
// would hand every holder the account the first of them linked. A
// client-credentials token needs nothing from this either, since its subject is
// the application's client id already.
func AppPrincipal(cons *Consumer, caller *identity.Principal) *identity.Principal {
	p := &identity.Principal{Subject: AppSubject(cons.ID), Method: identity.MethodAPIKey}
	if caller != nil {
		// Everything but the subject is carried over: an upstream that forwards
		// or exchanges the caller's own token still needs it, and the claims are
		// what an audit trail reads.
		copied := *caller
		p = &copied
		p.Subject = AppSubject(cons.ID)
	}
	claims := make(map[string]any, len(p.Claims)+2)
	for k, v := range p.Claims {
		claims[k] = v
	}
	claims["consumer_id"] = cons.ID.String()
	if caller != nil && caller.Subject != "" {
		claims[identity.ClaimCredentialSubject] = caller.Subject
	}
	p.Claims = claims
	return p
}

// AdmitsPrincipal applies the consumer's auth binding to the verified
// caller: a bearer token from a shared IdP must have been issued to an allowed
// client, and a client certificate must carry an allowed subject. API keys are
// bound to one consumer already, and a missing principal has nothing to bind.
func AdmitsPrincipal(cons *Consumer, principal *identity.Principal) bool {
	if cons == nil {
		return false
	}
	if principal == nil {
		return true
	}
	switch {
	case principal.Method.IsBearerToken():
		return cons.AuthBinding.AllowsClient(principal.Claims)
	case principal.Method == identity.MethodMTLS:
		return cons.AuthBinding.AllowsCertificateClaims(principal.Claims)
	default:
		return true
	}
}
