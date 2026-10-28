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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// keyCtx is ana's personal key on a gateway whose default is mode: a group
// key for keyGroup, or her personal key when keyGroup is empty. Either way the
// principal carries every group she belongs to.
func keyCtx(mode, keyGroup string, groups ...string) context.Context {
	claims := map[string]any{identity.ClaimGroups: groups}
	if keyGroup != "" {
		claims[identity.ClaimKeyGroup] = keyGroup
	}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: "ana", Method: identity.MethodPersonalKey, Claims: claims,
	})
	return appgateway.WithGateway(ctx, &gatewaydomain.Gateway{Metadata: gatewaydomain.WithStoreMode(nil, mode)})
}

// A group key's Store mode is its group's: not the owner's own policy, not the
// most permissive of her other groups. Without a policy on the group it is the
// gateway default, still not hers.
func TestModeResolverDecidesAGroupKeyByItsGroupAlone(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	r := NewModeResolver(&fakePolicies{items: []*storeaccessdomain.Policy{
		policy(gw, storeaccessdomain.PrincipalUser, "ana", gatewaydomain.StoreModeOpen),
		policy(gw, storeaccessdomain.PrincipalGroup, "eng", gatewaydomain.StoreModeNone),
		policy(gw, storeaccessdomain.PrincipalGroup, "sre", gatewaydomain.StoreModeOpen),
	}})
	for name, tc := range map[string]struct {
		ctx  context.Context
		want string
	}{
		"the eng key: eng's policy":                      {ctx: keyCtx(gatewaydomain.StoreModeCurated, "eng", "eng", "sre"), want: gatewaydomain.StoreModeNone},
		"the sre key: sre's policy":                      {ctx: keyCtx(gatewaydomain.StoreModeCurated, "sre", "eng", "sre"), want: gatewaydomain.StoreModeOpen},
		"a key for a group with no policy: the default":  {ctx: keyCtx(gatewaydomain.StoreModeCurated, "data", "data", "sre"), want: gatewaydomain.StoreModeCurated},
		"the personal key: ana's own policy":             {ctx: keyCtx(gatewaydomain.StoreModeCurated, "", "eng", "sre"), want: gatewaydomain.StoreModeOpen},
		"a token claiming a key group: ana's own policy": {ctx: withClaimedKeyGroup("eng"), want: gatewaydomain.StoreModeOpen},
	} {
		if got := r.Mode(tc.ctx, gw); got != tc.want {
			t.Fatalf("%s: mode = %q, want %q", name, got, tc.want)
		}
	}
	got := ResolveMode(context.Background(), r, ModeQuery{GatewayID: gw, Groups: []string{"eng"}, Fallback: gatewaydomain.StoreModeOpen})
	if got != gatewaydomain.StoreModeNone {
		t.Fatalf("a query naming only a group reads that group's policy, got %q", got)
	}
	got = ResolveMode(context.Background(), r, ModeQuery{GatewayID: gw, Fallback: gatewaydomain.StoreModeOpen})
	if got != gatewaydomain.StoreModeOpen {
		t.Fatalf("a query naming nobody keeps the fallback, got %q", got)
	}
}

// withClaimedKeyGroup is a signed-in session whose token carries the key group
// claim. Only the gateway builds a personal key's principal, so the claim is
// not read here.
func withClaimedKeyGroup(group string) context.Context {
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: "ana", Method: identity.MethodExternalJWT,
		Claims: map[string]any{identity.ClaimKeyGroup: group, identity.ClaimGroups: []string{"eng"}},
	})
	return appgateway.WithGateway(ctx, &gatewaydomain.Gateway{Metadata: gatewaydomain.WithStoreMode(nil, gatewaydomain.StoreModeCurated)})
}

// Under Selected a group key reaches what is granted to its group, and only
// that: a grant naming its owner, or another of her groups, does not count.
// The installs stay hers, whichever key opened the Store.
func TestScoperDecidesAGroupKeysGrantsByItsGroupAlone(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	github, linear, notion := githubRegistry(), shelfRegistry("linear"), shelfRegistry("notion")
	installs := &fakeInstalls{byPrincipal: []*installationdomain.Installation{
		mustInstall(t, gw, "ana", "github"), mustInstall(t, gw, "ana", "linear"), mustInstall(t, gw, "ana", "notion"),
	}}
	sc := newScoperT(t, installs,
		&fakeRegistries{items: []*registrydomain.Registry{github, linear, notion}},
		grantsOf(
			codeGrant(gw, "github", nil, []string{"ana"}),
			codeGrant(gw, "linear", []string{"eng"}, nil),
			codeGrant(gw, "notion", []string{"sre"}, nil),
		),
	)
	rc := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	exposed := func(ctx context.Context) map[string]bool {
		t.Helper()
		scoped, err := sc.Scope(ctx, rc)
		if err != nil {
			t.Fatalf("Scope: %v", err)
		}
		out := map[string]bool{}
		for _, reg := range scoped.Registries {
			out[reg.MCPTarget.Code] = true
		}
		return out
	}

	if got := exposed(keyCtx(gatewaydomain.StoreModeCurated, "eng", "eng", "sre")); len(got) != 1 || !got["linear"] {
		t.Fatalf("the eng key = %v, want only what eng is granted", got)
	}
	if got := exposed(keyCtx(gatewaydomain.StoreModeCurated, "data", "data", "eng", "sre")); len(got) != 0 {
		t.Fatalf("a key for an ungranted group = %v, want nothing", got)
	}
	if got := exposed(keyCtx(gatewaydomain.StoreModeCurated, "", "eng", "sre")); len(got) != 3 {
		t.Fatalf("the personal key = %v, want everything granted to ana or her groups", got)
	}
	if got := exposed(keyCtx(gatewaydomain.StoreModeOpen, "data", "data")); len(got) != 3 {
		t.Fatalf("under All a group key = %v, want every install", got)
	}
}

// An install made with a group key is decided for the group: a grant to its
// owner does not install it, a grant to the group does. It is the owner's
// install, and a request it files names the group.
func TestInstallGroupScopedIgnoresTheOwnersGrants(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	groupKey := InstallRequest{
		GatewayID: gw, PrincipalSub: "ana", Code: "github", InstalledBy: "ana",
		Groups: []string{"eng"}, GroupScoped: true, Reason: "the eng on-call needs it",
	}

	installs := &fakeInstalls{}
	toAna := newInstallerWithGrants(t, &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}, installs,
		grantsOf(codeGrant(gw, "github", nil, []string{"ana"})))
	res, err := toAna.Install(context.Background(), groupKey)
	if err != nil {
		t.Fatalf("Install: %v", err)
	}
	if !res.Pending {
		t.Fatalf("a server granted only to the owner must be a request for her group key, got %+v", res)
	}
	if got := installs.upserts[len(installs.upserts)-1]; got.PrincipalSub != "ana" || len(got.RequesterGroups) != 1 || got.RequesterGroups[0] != "eng" {
		t.Fatalf("the request = %+v, want ana's, naming the eng group", got)
	}
	personal := groupKey
	personal.GroupScoped, personal.Groups = false, []string{"eng", "sre"}
	if res, err = toAna.Install(context.Background(), personal); err != nil || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("the personal key keeps the owner's grant, got %+v, %v", res, err)
	}

	toEng := newInstallerWithGrants(t, &fakeRegistries{items: []*registrydomain.Registry{shelfRegistry("github")}}, &fakeInstalls{},
		grantsOf(codeGrant(gw, "github", []string{"eng"}, nil)))
	if res, err = toEng.Install(context.Background(), groupKey); err != nil || res.Status != installationdomain.StatusInstalled {
		t.Fatalf("a server granted to the group must install, got %+v, %v", res, err)
	}
}
