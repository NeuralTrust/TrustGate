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
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func forwardedGithub() *registrydomain.Registry {
	return authedRegistry("github", &registrydomain.MCPAuth{
		Mode: registrydomain.MCPAuthModeForwarded, Provider: "github", Registration: registrydomain.RegistrationAuto,
	})
}

func heldInstall(t *testing.T, gw ids.GatewayID, registryID ids.RegistryID) *installationdomain.Installation {
	t.Helper()
	in, err := installationdomain.New(gw, "alice", "github", "alice", nil)
	if err != nil {
		t.Fatalf("installation: %v", err)
	}
	in.RegistryID = registryID
	return in
}

// The instance a person already has answers an install of it as it stands:
// nothing is written, and whether it needs their account is read off the
// instance it is served by.
func TestInstalled_AnswersTheInstanceThePrincipalHolds(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	reg := forwardedGithub()
	held := heldInstall(t, gw, ids.RegistryID{})
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{held}}

	res, err := newInstaller(t, &fakeRegistries{items: []*registrydomain.Registry{reg}}, installs).
		Installed(context.Background(), InstallRequest{GatewayID: gw, PrincipalSub: "alice", Code: "github"})

	if err != nil {
		t.Fatalf("Installed: %v", err)
	}
	if !res.AlreadyInstalled || !res.RequiresAuth || res.InstanceID != held.ID.String() || res.Code != "github" {
		t.Fatalf("result = %+v, want the held instance, needing the user's account", res)
	}
	if len(installs.upserts) != 0 {
		t.Fatal("answering what the principal holds writes nothing")
	}
}

func TestInstalled_IsNotARequestOrSomethingTheyDoNotHave(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{forwardedGithub()}}
	pending := heldInstall(t, gw, ids.RegistryID{})
	pending.Status = installationdomain.StatusPendingApproval

	for name, installs := range map[string]*fakeInstalls{
		"nothing installed": {},
		"only a request":    {byCode: []*installationdomain.Installation{pending}},
	} {
		_, err := newInstaller(t, regs, installs).Installed(context.Background(), InstallRequest{GatewayID: gw, PrincipalSub: "alice", Code: "github"})
		if !errors.Is(err, ErrNotInstalled) {
			t.Fatalf("%s: err = %v, want ErrNotInstalled", name, err)
		}
	}
}

// Two instances held: the caller names which, or nothing is picked for them.
func TestInstalled_NeedsTheInstanceNamedWhenSeveralAreHeld(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	prod, sandbox := forwardedGithub(), forwardedGithub()
	regs := &fakeRegistries{items: []*registrydomain.Registry{prod, sandbox}}
	installs := &fakeInstalls{byCode: []*installationdomain.Installation{heldInstall(t, gw, prod.ID), heldInstall(t, gw, sandbox.ID)}}
	installer := newInstaller(t, regs, installs)

	if _, err := installer.Installed(context.Background(), InstallRequest{GatewayID: gw, PrincipalSub: "alice", Code: "github"}); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("err = %v, want ErrNotInstalled when none is named", err)
	}
	res, err := installer.Installed(context.Background(), InstallRequest{GatewayID: gw, PrincipalSub: "alice", Code: "github", RegistryID: sandbox.ID})
	if err != nil || res.RegistryID != sandbox.ID {
		t.Fatalf("result = %+v / %v, want the sandbox instance", res, err)
	}
}
