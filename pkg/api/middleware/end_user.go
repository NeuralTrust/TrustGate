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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/gofiber/fiber/v2"
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
// sender someone else's policy. `end_user_detection_test.go` locks that
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
		// Open WebUI sends these when ENABLE_FORWARD_USER_INFO_HEADERS is on.
		source: "open_webui",
		id:     "X-OpenWebUI-User-Id",
		email:  "X-OpenWebUI-User-Email",
		name:   "X-OpenWebUI-User-Name",
		role:   "X-OpenWebUI-User-Role",
	},
}

// detectEndUser reads the first known end-user header set the request carries.
// Returns nil when the request carries none, which is the common case and must
// stay free: a request without these headers is attributed exactly as before.
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
		// A set that contributed nothing did not match; the next one may.
		if endUser.ID != "" || endUser.Email != "" || endUser.Name != "" || endUser.Role != "" {
			return &endUser
		}
	}
	return nil
}

func endUserHeaderValue(c *fiber.Ctx, header string) string {
	value := strings.TrimSpace(c.Get(header))
	if len(value) > maxEndUserValueLen {
		return value[:maxEndUserValueLen]
	}
	return value
}
