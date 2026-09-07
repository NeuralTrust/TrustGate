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

package mcp

import (
	"errors"
	"log/slog"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A per-user host value that passes the segment charset must still not be able
// to aim the shared registry at the gateway's own network.
func TestComposerTarget_RefusesPrivateOrMetadataHosts(t *testing.T) {
	for _, host := range []string{"169.254.169.254", "metadata.google.internal", "localhost", "10.0.0.5", "vault.corp.internal"} {
		reg := urlVarRegistry(t)
		finder := fakeInstallFinder{byCode: map[string]map[string]string{
			"snowflake": {"account_url": host, "database": "ANALYTICS"},
		}}
		c := &composer{logger: slog.New(slog.DiscardHandler), urlvars: NewURLValueResolver(finder, nil)}
		rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP})

		_, err := c.target(subCtx("ana"), rc, reg)
		if !errors.Is(err, registrydomain.ErrUnsafeUpstreamHost) {
			t.Fatalf("%s: err = %v, want ErrUnsafeUpstreamHost", host, err)
		}
	}
}

func TestComposerTarget_ResolvedURLIsPrivateNetworkRestricted(t *testing.T) {
	reg := urlVarRegistry(t)
	finder := fakeInstallFinder{byCode: map[string]map[string]string{
		"snowflake": {"account_url": "acme.snowflakecomputing.com", "database": "ANALYTICS"},
	}}
	c := &composer{logger: slog.New(slog.DiscardHandler), urlvars: NewURLValueResolver(finder, nil)}
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP})

	tgt, err := c.target(subCtx("ana"), rc, reg)
	if err != nil {
		t.Fatalf("target: %v", err)
	}
	if !tgt.RestrictPrivateNetwork {
		t.Fatal("a target built from per-user URL variables must carry the dial-time private-network restriction")
	}

	// An admin-fixed URL is not per-user input: no restriction, loopback allowed
	// (this is what every httptest-based test relies on).
	fixed := mcpRegistry(t, "fixed", "http://127.0.0.1:1/mcp")
	tgt, err = c.target(subCtx("ana"), rc, fixed)
	if err != nil {
		t.Fatalf("fixed target: %v", err)
	}
	if tgt.RestrictPrivateNetwork {
		t.Fatal("an admin-fixed URL must not be private-network restricted")
	}
}
