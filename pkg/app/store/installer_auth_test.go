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

package store

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func authedRegistry(code string, auth *registrydomain.MCPAuth) *registrydomain.Registry {
	reg := shelfRegistry(code)
	reg.MCPTarget.Auth = auth
	return reg
}

// TestInstallOfStaticInstanceNeedsNoUserConnect: the catalog entry requires auth,
// but the admin shelved the instance with their own API key. There is no account
// for the user to connect, so the install must not advertise one.
func TestInstallOfStaticInstanceNeedsNoUserConnect(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		authedRegistry("github", &registrydomain.MCPAuth{
			Mode:   registrydomain.MCPAuthModeStatic,
			Header: "Authorization",
			Value:  "Bearer ghp_token",
		}),
	}}
	res, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresAuth {
		t.Fatalf("a statically authenticated instance has no account to connect, got %+v", res)
	}
}

// TestInstallOfForwardedInstanceNeedsUserConnect: the same entry shelved for
// per-user OAuth still asks the user to sign in.
func TestInstallOfForwardedInstanceNeedsUserConnect(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{
		authedRegistry("github", &registrydomain.MCPAuth{
			Mode:         registrydomain.MCPAuthModeForwarded,
			Provider:     "github",
			Registration: registrydomain.RegistrationAuto,
		}),
	}}
	res, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.RequiresAuth {
		t.Fatalf("a forwarded instance needs the user's own account, got %+v", res)
	}
}

// TestInstallOfNamedStaticInstanceNeedsNoUserConnect: the same answer when the
// caller named the instance rather than letting the installer pick it.
func TestInstallOfNamedStaticInstanceNeedsNoUserConnect(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	static := authedRegistry("github", &registrydomain.MCPAuth{
		Mode:   registrydomain.MCPAuthModeStatic,
		Header: "Authorization",
		Value:  "Bearer ghp_token",
	})
	forwarded := authedRegistry("github", &registrydomain.MCPAuth{
		Mode:     registrydomain.MCPAuthModeForwarded,
		Provider: "github",
	})
	regs := &fakeRegistries{items: []*registrydomain.Registry{static, forwarded}}
	in := openReq(gw, "github")
	in.RegistryID = static.ID
	res, err := newInstaller(t, regs, &fakeInstalls{}).Install(context.Background(), in)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if res.RequiresAuth {
		t.Fatalf("the named instance authenticates statically, got %+v", res)
	}
}

// TestInstallMaterialisedInstanceKeepsCatalogRequiresAuth: nothing is shelved yet,
// so the registry the installer materialises is the catalog's own OAuth shape and
// the answer comes from the entry.
func TestInstallMaterialisedInstanceKeepsCatalogRequiresAuth(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{}
	res, err := newInstallerWithEnsurer(t, regs, &fakeInstalls{}, &fakeEnsurer{addTo: regs}).
		Install(context.Background(), openReq(gw, "github"))
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.RequiresAuth {
		t.Fatalf("a materialised instance follows the catalog entry, got %+v", res)
	}
}
