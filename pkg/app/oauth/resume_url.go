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
	"fmt"
	"net"
	"net/url"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

const maxResumeURLLen = 2048

// NormalizeResumeURL checks a URL a caller asked the connect page to send the
// user back to once their account is connected.
//
// The page links to it and, right after a connect, navigates to it on its own,
// so it is held to what a web app the user came from can be: an absolute https
// URL, or http on a loopback host for local development. Anything else — a
// script, a data or custom scheme, a relative path, credentials in the URL — is
// refused rather than rendered. Empty is allowed and means nowhere to go back to.
//
// A client redirect parked by the authorization chain (ChainURL) is not held to
// this: it is the redirect_uri that client registered, and may well be a custom
// scheme that opens a desktop app.
func NormalizeResumeURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	invalid := fmt.Errorf("resume_url must be an absolute https URL: %w", commonerrors.ErrValidation)
	if len(raw) > maxResumeURLLen {
		return "", invalid
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" {
		return "", invalid
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", invalid
		}
	default:
		return "", invalid
	}
	return u.String(), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
