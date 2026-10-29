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

// Package dataplane holds what a config-sync data plane reports about itself.
// The control plane records it per stream so the console can tell a live
// gateway from a silent one and show what each one runs.
package dataplane

import (
	"net/url"
	"strings"
)

// Heartbeat is what a data plane reports on its Sync stream: the build it runs,
// where it runs and the TrustGuard its guardrail policies call. None of it is
// a secret.
type Heartbeat struct {
	Version            string
	Region             string
	DeploymentType     string
	TrustGuardBaseURL  string
	TrustGuardClientID string
}

// StreamKey names one data-plane Sync stream: the verified scope of its token
// and the instance id it announced.
type StreamKey struct {
	Scope      string
	InstanceID string
}

// ReportableURL returns raw without userinfo, query or fragment, so a URL
// that embeds credentials is never reported. It returns "" for a value that
// is not an absolute http(s) URL.
func ReportableURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return ""
	}
	clean := url.URL{Scheme: u.Scheme, Host: u.Host, Path: strings.TrimRight(u.Path, "/")}
	return clean.String()
}
