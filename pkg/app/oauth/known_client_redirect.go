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
	"context"
	"log/slog"
	"net/url"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// knownClientRedirectMetric counts authorize requests that relied on an
// upstream identity provider's client_id instead of a client registration, by
// redirect kind. It sizes how many clients a registration requirement on that
// path would affect (ENG-1984).
const knownClientRedirectMetric = "trustgate.oauth.known_client_redirect"

const (
	redirectKindLoopback   = "loopback"
	redirectKindPrivateUse = "private_use"
	redirectKindHTTPS      = "https"
)

// recordKnownClientRedirect counts every redirect kind and logs the https
// ones with their origin, which names the client application; the path and
// query are left out.
func recordKnownClientRedirect(ctx context.Context, clientID, redirectURI string) {
	kind, origin := classifyKnownClientRedirect(redirectURI)
	if kind == redirectKindHTTPS {
		slog.Info("oauth: authorize relied on an upstream client_id with an https redirect",
			slog.String("client_id", clientID),
			slog.String("redirect_origin", origin))
	}
	counter, err := otel.Meter("trustgate/oauth").Int64Counter(
		knownClientRedirectMetric,
		metric.WithDescription("authorize requests accepted on an upstream identity provider client_id, by redirect_uri kind"),
	)
	if err != nil {
		slog.Warn("failed to create known-client redirect counter", slog.String("error", err.Error()))
		return
	}
	counter.Add(ctx, 1, metric.WithAttributes(attribute.String("redirect_kind", kind)))
}

// classifyKnownClientRedirect expects a redirect_uri IsAcceptableRedirectURI
// has already accepted, so plain http here is always loopback.
func classifyKnownClientRedirect(raw string) (kind, origin string) {
	u, err := url.Parse(raw)
	if err != nil {
		return redirectKindHTTPS, ""
	}
	origin = u.Scheme + "://" + u.Host
	switch {
	case u.Scheme == "http", u.Scheme == "https" && isLoopbackHost(u.Hostname()):
		return redirectKindLoopback, origin
	case u.Scheme == "https":
		return redirectKindHTTPS, origin
	default:
		return redirectKindPrivateUse, origin
	}
}
