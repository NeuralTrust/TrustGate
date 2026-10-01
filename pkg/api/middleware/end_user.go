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
	"net/url"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
)

// A chat front-end like Open WebUI authenticates to the gateway with one shared
// API key, so every one of its users arrives as the same consumer. The end user
// it was actually serving travels in headers it forwards, and reading them is
// what makes per-person attribution possible without asking the customer to
// configure anything.
//
// Those headers are asserted by the caller, not verified by us: anyone holding
// that API key can put any name in them. So what is read here is TELEMETRY ONLY
// — it describes a request, it never decides anything about it. It must not
// reach the principal (see trace.Metadata.Principal*), which authorizes and
// reaches TrustGuard's gate attributes, where a forged value would buy the
// sender someone else's policy. `pkg/infra/plugins/trustguard/end_user_isolation_test.go` locks that
// separation; keep it locked.

// maxEndUserValueLen bounds each captured value. The headers are caller-supplied
// and unbounded, and these fields are labels in telemetry — a value longer than
// this is not a name or an email, it is someone filling our storage.
const maxEndUserValueLen = 256

// endUserHeaderSet is one front-end's convention for forwarding its signed-in
// user. Supporting another client is adding an entry.
type endUserHeaderSet struct {
	// source names the convention that matched, and is recorded alongside the
	// values so a reader can tell where an attribution came from.
	source string
	id     string
	email  string
	name   string
	role   string
}

var endUserHeaderSets = []endUserHeaderSet{
	{
		// Our own namespace, first because it is the one a customer sets
		// deliberately: any client we do not know by name can attribute its
		// users with these, and a request carrying both these and a vendor's
		// own headers meant these.
		source: events.EndUserSourceTrustGate,
		id:     "X-TG-User-Id",
		email:  "X-TG-User-Email",
		name:   "X-TG-User-Name",
		role:   "X-TG-User-Role",
	},
	{
		// Open WebUI sends these when ENABLE_FORWARD_USER_INFO_HEADERS is on.
		source: events.EndUserSourceOpenWebUI,
		id:     "X-OpenWebUI-User-Id",
		email:  "X-OpenWebUI-User-Email",
		name:   "X-OpenWebUI-User-Name",
		role:   "X-OpenWebUI-User-Role",
	},
}

// Open WebUI sends one HS256 JWT in this header instead of its plain
// X-OpenWebUI-User-* headers once FORWARD_USER_INFO_HEADER_JWT_SECRET is set.
// The claims carry the same user, and the iss it always stamps tells its token
// apart from anything else a caller might put there.
const (
	openWebUIUserJWTHeader = "X-OpenWebUI-User-Jwt"
	openWebUIJWTIssuer     = "open-webui"
)

// maxEndUserJWTLen bounds the token before it is parsed. Open WebUI's is a few
// hundred bytes; anything far past that is not one of its tokens.
const maxEndUserJWTLen = 4096

// detectEndUser reads the first known end-user header set the request carries,
// then Open WebUI's signed user JWT. Returns nil when the request carries none,
// which is the common case and must stay free: a request without these headers
// is attributed exactly as before.
func detectEndUser(c *fiber.Ctx) *trace.EndUser {
	if c == nil {
		return nil
	}
	for _, set := range endUserHeaderSets {
		endUser := trace.EndUser{
			Source: set.source,
			ID:     endUserHeaderValue(c, set.id),
			Email:  endUserHeaderValue(c, set.email),
			Name:   endUserHeaderValue(c, set.name),
			Role:   endUserHeaderValue(c, set.role),
		}
		if set.source == events.EndUserSourceOpenWebUI {
			// Open WebUI percent-encodes the name (so "José" arrives as
			// "Jos%C3%A9"); a value that does not decode is kept as sent.
			if name, err := url.PathUnescape(endUser.Name); err == nil {
				endUser.Name = boundEndUserValue(strings.TrimSpace(name))
			}
		}
		// A set that contributed nothing did not match; the next one may.
		if !endUserIsEmpty(endUser) {
			return &endUser
		}
	}
	return openWebUIJWTEndUser(c)
}

// openWebUIJWTEndUser reads the user from Open WebUI's signed user JWT.
//
// The signature is NOT checked: that takes the secret the customer set in Open
// WebUI, which the gateway does not hold. Unverified, the token says no more
// than the plain headers it replaces — anyone holding the API key could mint
// one — so it is read under the same telemetry-only rule as they are.
func openWebUIJWTEndUser(c *fiber.Ctx) *trace.EndUser {
	token := strings.TrimSpace(c.Get(openWebUIUserJWTHeader))
	if token == "" || len(token) > maxEndUserJWTLen {
		return nil
	}
	claims := jwt.MapClaims{}
	if _, _, err := jwt.NewParser().ParseUnverified(token, claims); err != nil {
		return nil
	}
	if iss, _ := claims["iss"].(string); iss != openWebUIJWTIssuer {
		return nil
	}
	endUser := trace.EndUser{
		Source: events.EndUserSourceOpenWebUI,
		ID:     endUserClaim(claims, "sub"),
		Email:  endUserClaim(claims, "email"),
		Name:   endUserClaim(claims, "name"),
		Role:   endUserClaim(claims, "role"),
	}
	if endUserIsEmpty(endUser) {
		return nil
	}
	return &endUser
}

func endUserIsEmpty(endUser trace.EndUser) bool {
	return endUser.ID == "" && endUser.Email == "" && endUser.Name == "" && endUser.Role == ""
}

func endUserClaim(claims jwt.MapClaims, name string) string {
	value, _ := claims[name].(string)
	return boundEndUserValue(strings.TrimSpace(value))
}

func endUserHeaderValue(c *fiber.Ctx, header string) string {
	return boundEndUserValue(strings.TrimSpace(c.Get(header)))
}

func boundEndUserValue(value string) string {
	if len(value) > maxEndUserValueLen {
		return value[:maxEndUserValueLen]
	}
	return value
}
