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
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A request an approver has to decide is the one place the reason is read, so
// that is where it is kept.
func TestInstallKeepsTheReasonOnARequest(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	installs := &fakeInstalls{}
	inst := newInstaller(t, regs, installs)

	res, err := inst.Install(context.Background(), InstallRequest{
		GatewayID:    gw,
		PrincipalSub: "ana",
		Code:         "github",
		InstalledBy:  "ana",
		Reason:       "  I need to triage issues on the platform repo  ",
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if !res.Pending {
		t.Fatalf("expected a request under Selected access with no grant, got %+v", res)
	}
	if len(installs.upserts) != 1 {
		t.Fatalf("expected one row, got %d", len(installs.upserts))
	}
	if got := installs.upserts[0].Reason; got != "I need to triage issues on the platform repo" {
		t.Fatalf("reason = %q, want the requester's words, trimmed", got)
	}
}

// An install that needs no decision asks nobody, so there is nobody to read a
// reason and nothing to keep.
func TestInstallDropsTheReasonWhenNothingIsDecided(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	regs := &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}
	installs := &fakeInstalls{}
	inst := newInstaller(t, regs, installs)

	res, err := inst.Install(context.Background(), InstallRequest{
		GatewayID:    gw,
		PrincipalSub: "ana",
		Code:         "github",
		InstalledBy:  "ana",
		OpenMode:     true,
		Reason:       "just browsing",
	})
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	if res.Pending {
		t.Fatalf("open mode installs rather than requests, got %+v", res)
	}
	if got := installs.upserts[0].Reason; got != "" {
		t.Fatalf("reason = %q, want none on an install nobody decides", got)
	}
}

// The reason is free text a user typed. The write boundary bounds it, so no
// caller can put an unbounded string in the approval queue.
func TestInstallationRefusesAnOverlongReason(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	in, err := installationdomain.New(gw, "ana", "github", "ana", nil)
	if err != nil {
		t.Fatalf("new installation: %v", err)
	}
	in.Reason = strings.Repeat("x", installationdomain.MaxReasonLength)
	if err := in.Validate(); err != nil {
		t.Fatalf("a reason at the limit must be accepted: %v", err)
	}
	in.Reason = strings.Repeat("x", installationdomain.MaxReasonLength+1)
	if err := in.Validate(); err == nil {
		t.Fatal("a reason past the limit must be refused")
	}
}
