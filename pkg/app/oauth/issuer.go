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
	"log/slog"
	"net/url"
	"strings"
)

// IssuersEqual reports whether a and b identify the same issuer after trimming a trailing slash.
func IssuersEqual(a, b string) bool {
	return issuersEqual(a, b)
}

const (
	applicationTypeWeb    = "web"
	applicationTypeNative = "native"
)

func issuersEqual(a, b string) bool {
	return strings.TrimSuffix(a, "/") == strings.TrimSuffix(b, "/")
}

func validateResponseISS(got, expected string, advertised bool) error {
	if got == "" {
		if advertised {
			return oauthErr("invalid_request", "missing iss")
		}
		return nil
	}
	if !issuersEqual(got, expected) {
		return oauthErr("invalid_request", "iss mismatch")
	}
	return nil
}

func logIssuerMismatch(expected, got, gatewayID, provider, key string) {
	slog.Warn("oauth.issuer_mismatch",
		"expected_issuer", expected,
		"got_issuer", got,
		"gateway_id", gatewayID,
		"provider", provider,
		"key", key,
	)
}

func logInvalidMetadata(expected, metadataIssuer, key string) {
	slog.Warn("oauth.invalid_metadata",
		"expected_issuer", expected,
		"metadata_issuer", metadataIssuer,
		"key", key,
	)
}

func resolveApplicationType(requested string, uris []string) (string, error) {
	inferred := applicationTypeForURIs(uris)
	if inferred == "" {
		return "", oauthErr("invalid_client_metadata", "redirect_uris mix incompatible application types")
	}
	appType := strings.ToLower(strings.TrimSpace(requested))
	switch appType {
	case "":
		return inferred, nil
	case applicationTypeWeb, applicationTypeNative:
		if appType != inferred {
			return "", oauthErr("invalid_client_metadata", "application_type is inconsistent with redirect_uris")
		}
		return appType, nil
	default:
		return "", oauthErr("invalid_client_metadata", "application_type must be web or native")
	}
}

func applicationTypeForURIs(uris []string) string {
	var inferred string
	for _, uri := range uris {
		class := redirectURIApplicationType(uri)
		if class == "" {
			return ""
		}
		if inferred == "" {
			inferred = class
			continue
		}
		if inferred != class {
			return ""
		}
	}
	return inferred
}

func redirectURIApplicationType(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Fragment != "" {
		return ""
	}
	switch u.Scheme {
	case "https":
		if u.Host == "" {
			return ""
		}
		return applicationTypeWeb
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return applicationTypeNative
		}
		return ""
	default:
		if isPrivateUseRedirectURI(u) {
			return applicationTypeNative
		}
		return ""
	}
}
