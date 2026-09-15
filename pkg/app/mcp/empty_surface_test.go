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
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestEmptySurfaceInsteadOfError(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	application := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Type: consumerdomain.TypeMCP}}
	forUsers := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{
		ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Type: consumerdomain.TypeMCP,
		Identity: consumerdomain.Identity{ActsForUsers: true, Source: consumerdomain.IdentitySourcePlatform},
	}}
	store := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}

	// A pending consent degrades to an empty list for everyone.
	consent := &ConsentRequiredError{Provider: "github"}
	for _, rc := range []*appconsumer.RoutableConsumer{application, forUsers, store} {
		if !emptySurfaceInsteadOfError(rc, consent) {
			t.Fatal("a pending consent must yield an empty surface, not an error")
		}
	}
	// No exposed registry is an empty surface only where the surface is per
	// person; an application consumer without registries is a misconfiguration.
	if emptySurfaceInsteadOfError(application, ErrNoMCPRegistries) {
		t.Fatal("an application consumer without registries must surface the error")
	}
	if !emptySurfaceInsteadOfError(forUsers, ErrNoMCPRegistries) || !emptySurfaceInsteadOfError(store, ErrNoMCPRegistries) {
		t.Fatal("an acts-for-users consumer with nothing exposed lists an empty surface")
	}
	if !emptySurfaceInsteadOfError(forUsers, ErrUpstreamUnavailable) {
		t.Fatal("an unreachable upstream degrades to an empty surface for acts-for-users consumers")
	}
	if emptySurfaceInsteadOfError(forUsers, errors.New("boom")) {
		t.Fatal("other errors still fail")
	}
}
