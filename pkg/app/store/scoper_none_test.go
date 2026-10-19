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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// A policy read that fails is not a resolved None. ResolveMode fails closed to
// curated, and a grant that names the principal still exposes the install —
// the same answer as before this mode started hiding granted servers.
func TestScoperPolicyReadFailureStillHonorsGrants(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	shelf := githubRegistry()
	sc, err := NewScoper(
		&fakeInstalls{byPrincipal: []*installationdomain.Installation{mustInstall(t, gw, "ana", "github")}},
		&fakeRegistries{items: []*registrydomain.Registry{shelf}},
		grantsOf(codeGrant(gw, "github", nil, []string{"ana"})),
		WithScoperModes(NewModeResolver(&fakePolicies{err: errors.New("db down")})),
	)
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}
	// The token still says None, and the gateway default is All. Neither is
	// consulted: the failed read is curated, and the grant decides.
	ctx := appgateway.WithGateway(identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: "ana",
		Method:  identity.MethodOAuth,
		Claims:  map[string]any{identity.ClaimStoreAccess: gatewaydomain.StoreModeNone},
	}), &gatewaydomain.Gateway{Metadata: gatewaydomain.WithStoreMode(nil, gatewaydomain.StoreModeOpen)})
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}

	scoped, err := sc.Scope(ctx, rc)
	if err != nil {
		t.Fatalf("Scope: %v", err)
	}
	if len(scoped.Registries) != 1 || scoped.Registries[0] != shelf {
		t.Fatalf("unresolved mode must keep the granted install, got %+v", scoped.Registries)
	}
}
