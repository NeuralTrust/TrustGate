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

package client

import (
	"net/http"
	"testing"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
)

func TestRestrictedTargetTransportIgnoresEnvironmentProxy(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.example:3128")
	t.Setenv("HTTP_PROXY", "http://proxy.example:3128")

	restricted, ok := transportFor(appmcp.Target{RestrictPrivateNetwork: true}).(*http.Transport)
	if !ok {
		t.Fatal("restricted target transport is not an *http.Transport")
	}
	if restricted.Proxy != nil {
		t.Fatal("restricted target transport must connect directly, without a proxy")
	}
	if restricted.DialContext == nil {
		t.Fatal("restricted target transport must keep its dialer")
	}

	rebuilt, ok := newUpstreamTransport(dialPublicOnly, true).(*http.Transport)
	if !ok || rebuilt.Proxy != nil {
		t.Fatal("a restricted transport built with a proxy in the environment must not use it")
	}
}

func TestFixedTargetTransportKeepsEnvironmentProxy(t *testing.T) {
	t.Parallel()
	fixed, ok := transportFor(appmcp.Target{}).(*http.Transport)
	if !ok {
		t.Fatal("fixed target transport is not an *http.Transport")
	}
	if fixed.Proxy == nil {
		t.Fatal("fixed target transport must keep honouring the environment proxy")
	}
}
