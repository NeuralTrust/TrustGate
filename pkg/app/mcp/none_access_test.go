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
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appgateway "github.com/NeuralTrust/TrustGate/pkg/app/gateway"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	installationdomain "github.com/NeuralTrust/TrustGate/pkg/domain/installation"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
)

// A principal whose access mode is None keeps the install and the grants, and
// loses the surface: tools/list, the server listing, and tools/call. The
// personal key and the MCP session are the two credentials that reach the
// Store as that person; both are decided by the same scoper. Putting the mode
// back to Selected restores the granted servers and leaves an ungranted
// install hidden. Another user in the org, a user on All, a user whose group
// policy is All, and a consumer an admin bound are unchanged.
func TestNoneAccessRevokesListAndCallOnBothCredentials(t *testing.T) {
	gw := ids.New[ids.GatewayKind]()
	dynatrace := accessShelf("Dynatrace", "dynatrace", "https://dynatrace.example/mcp")
	pagerduty := accessShelf("PagerDuty", "pagerduty", "https://pagerduty.example/mcp")
	linear := accessShelf("Linear", "linear", "https://linear.example/mcp")
	bound := accessShelf("Internal", "internal", "https://internal.example/mcp")

	direct, err := storeaccessdomain.New(gw, "dynatrace", ids.RegistryID{}, nil, []string{"qa16"})
	if err != nil {
		t.Fatalf("direct grant: %v", err)
	}
	group, err := storeaccessdomain.New(gw, "pagerduty", ids.RegistryID{}, []string{"qa-portal-grp"}, nil)
	if err != nil {
		t.Fatalf("group grant: %v", err)
	}
	installs := []*installationdomain.Installation{
		accessInstall(t, gw, "qa16", "dynatrace"),
		accessInstall(t, gw, "qa16", "pagerduty"),
		accessInstall(t, gw, "qa16", "linear"),
		accessInstall(t, gw, "bob", "pagerduty"),
		accessInstall(t, gw, "admin", "dynatrace"),
		accessInstall(t, gw, "glass", "pagerduty"),
	}
	qa16Mode := accessPolicy(t, gw, storeaccessdomain.PrincipalUser, "qa16", gatewaydomain.StoreModeNone)
	policies := &accessPolicies{items: []*storeaccessdomain.Policy{
		qa16Mode,
		accessPolicy(t, gw, storeaccessdomain.PrincipalUser, "bob", gatewaydomain.StoreModeCurated),
		accessPolicy(t, gw, storeaccessdomain.PrincipalUser, "admin", gatewaydomain.StoreModeOpen),
		accessPolicy(t, gw, storeaccessdomain.PrincipalGroup, "break-glass", gatewaydomain.StoreModeOpen),
	}}
	scoper, err := appstore.NewScoper(
		&accessInstalls{rows: installs},
		&accessRegistries{items: []*registrydomain.Registry{dynatrace, pagerduty, linear}},
		&accessGrants{items: []*storeaccessdomain.Grant{direct, group}},
		appstore.WithScoperModes(appstore.NewModeResolver(policies)),
	)
	if err != nil {
		t.Fatalf("NewScoper: %v", err)
	}

	dynatraceUp := &fakeUpstream{tools: tools("find-documents"), result: json.RawMessage(`{"server":"dynatrace"}`)}
	pagerdutyUp := &fakeUpstream{tools: tools("list-incidents"), result: json.RawMessage(`{"server":"pagerduty"}`)}
	linearUp := &fakeUpstream{tools: tools("list-issues"), result: json.RawMessage(`{"server":"linear"}`)}
	boundUp := &fakeUpstream{tools: tools("ping"), result: json.RawMessage(`{"server":"internal"}`)}
	inner := &fakeDialer{upstreams: map[string]*fakeUpstream{
		dynatrace.MCPTarget.URL: dynatraceUp,
		pagerduty.MCPTarget.URL: pagerdutyUp,
		linear.MCPTarget.URL:    linearUp,
		bound.MCPTarget.URL:     boundUp,
	}}
	dialer := newCountingDialer(func(url string) (Upstream, error) {
		return inner.Connect(context.Background(), Target{URL: url})
	})
	inventory, err := NewInventoryTool(newTestComposer(dialer), nil)
	if err != nil {
		t.Fatalf("NewInventoryTool: %v", err)
	}
	dispatcher := NewRPCDispatcher(newTestComposer(dialer), NewPluginRunner(nil, nil), nil, nil, nil).
		WithStoreScoper(scoper).
		WithInventoryTool(inventory)
	store := &appconsumer.RoutableConsumer{Consumer: consumerdomain.BuildStoreConsumer(gw)}
	application := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Type: consumerdomain.TypeMCP,
		},
		Registries: []*registrydomain.Registry{bound},
	}

	// The personal key carries no store_access claim. The session token still
	// says All, from before the admin changed the policy. The live policy wins
	// on both.
	for _, cred := range []struct {
		name   string
		method identity.Method
		claim  string
	}{
		{name: "personal key", method: identity.MethodPersonalKey},
		{name: "mcp session", method: identity.MethodOAuth, claim: gatewaydomain.StoreModeOpen},
	} {
		t.Run(cred.name, func(t *testing.T) {
			ctx := accessCtx(cred.method, "qa16", cred.claim, "qa-portal-grp")
			resetDials(dialer)
			clearCalls(dynatraceUp, pagerdutyUp, linearUp, boundUp)

			if got := upstreamTools(accessList(t, dispatcher, ctx, store)); len(got) != 0 {
				t.Fatalf("tools/list = %v, want no upstream tools", got)
			}
			if n := accessServers(t, dispatcher, ctx, store); n != 0 {
				t.Fatalf("server listing = %d, want 0", n)
			}
			_, err := accessCall(dispatcher, ctx, store, "dynatrace_find-documents")
			if !errors.Is(err, ErrToolNotFound) || errors.Is(err, ErrNoMCPRegistries) {
				t.Fatalf("tools/call err = %v, want Unknown tool", err)
			}
			if dialCount(dialer) != 0 || dynatraceUp.lastCall != "" || pagerdutyUp.lastCall != "" {
				t.Fatalf("None must not dial upstream, dials=%d dynatrace=%q pagerduty=%q",
					dialCount(dialer), dynatraceUp.lastCall, pagerdutyUp.lastCall)
			}

			// The same person on a consumer an admin bound still has that surface.
			boundNames := accessList(t, dispatcher, ctx, application)
			if !containsTool(boundNames, "ping") {
				t.Fatalf("admin-bound consumer tools = %v, want ping", boundNames)
			}
			if _, err := accessCall(dispatcher, ctx, application, nameWith(t, boundNames, "ping")); err != nil {
				t.Fatalf("admin-bound call: %v", err)
			}
			if boundUp.lastCall != "ping" {
				t.Fatalf("admin-bound upstream call = %q, want ping", boundUp.lastCall)
			}
		})
	}

	bob := accessCtx(identity.MethodPersonalKey, "bob", "", "qa-portal-grp")
	bobNames := accessList(t, dispatcher, bob, store)
	if !containsTool(bobNames, "list-incidents") || containsTool(bobNames, "find-documents") || containsTool(bobNames, "list-issues") {
		t.Fatalf("other user tools = %v, want only the group grant", bobNames)
	}
	if _, err := accessCall(dispatcher, bob, store, nameWith(t, bobNames, "list-incidents")); err != nil {
		t.Fatalf("other user call: %v", err)
	}

	admin := accessCtx(identity.MethodOAuth, "admin", gatewaydomain.StoreModeNone)
	adminNames := accessList(t, dispatcher, admin, store)
	if !containsTool(adminNames, "find-documents") {
		t.Fatalf("All-mode user tools = %v, want the install without a grant", adminNames)
	}
	if _, err := accessCall(dispatcher, admin, store, nameWith(t, adminNames, "find-documents")); err != nil {
		t.Fatalf("All-mode user call: %v", err)
	}

	glass := accessCtx(identity.MethodPersonalKey, "glass", "", "break-glass")
	glassNames := accessList(t, dispatcher, glass, store)
	if !containsTool(glassNames, "list-incidents") {
		t.Fatalf("break-glass group tools = %v, want the install", glassNames)
	}
	if _, err := accessCall(dispatcher, glass, store, nameWith(t, glassNames, "list-incidents")); err != nil {
		t.Fatalf("break-glass group call: %v", err)
	}

	qa16Mode.Mode = gatewaydomain.StoreModeCurated
	for _, cred := range []struct {
		name   string
		method identity.Method
		claim  string
	}{
		{name: "personal key", method: identity.MethodPersonalKey},
		{name: "mcp session", method: identity.MethodOAuth, claim: gatewaydomain.StoreModeOpen},
	} {
		t.Run("selected/"+cred.name, func(t *testing.T) {
			ctx := accessCtx(cred.method, "qa16", cred.claim, "qa-portal-grp")
			clearCalls(dynatraceUp, pagerdutyUp, linearUp)
			names := accessList(t, dispatcher, ctx, store)
			if !containsTool(names, "find-documents") || !containsTool(names, "list-incidents") || containsTool(names, "list-issues") {
				t.Fatalf("Selected tools = %v, want the direct and group grants only", names)
			}
			if n := accessServers(t, dispatcher, ctx, store); n != 2 {
				t.Fatalf("server listing = %d, want the two granted servers", n)
			}
			if _, err := accessCall(dispatcher, ctx, store, nameWith(t, names, "find-documents")); err != nil {
				t.Fatalf("direct-grant call: %v", err)
			}
			if _, err := accessCall(dispatcher, ctx, store, nameWith(t, names, "list-incidents")); err != nil {
				t.Fatalf("group-grant call: %v", err)
			}
			if dynatraceUp.lastCall != "find-documents" || pagerdutyUp.lastCall != "list-incidents" || linearUp.lastCall != "" {
				t.Fatalf("upstream calls dynatrace=%q pagerduty=%q linear=%q",
					dynatraceUp.lastCall, pagerdutyUp.lastCall, linearUp.lastCall)
			}
		})
	}

	if len(installs) != 6 {
		t.Fatalf("install rows = %d, want them left in place", len(installs))
	}
	for _, row := range installs {
		if row.Status != installationdomain.StatusInstalled {
			t.Fatalf("install %s/%s status = %s", row.PrincipalSub, row.CatalogCode, row.Status)
		}
	}
	if len(direct.Users) != 1 || direct.Users[0] != "qa16" || len(group.Groups) != 1 || group.Groups[0] != "qa-portal-grp" {
		t.Fatalf("grants changed: direct=%+v group=%+v", direct, group)
	}
}

func accessShelf(name, code, url string) *registrydomain.Registry {
	return &registrydomain.Registry{
		ID:      ids.New[ids.RegistryKind](),
		Name:    name,
		Enabled: true,
		Type:    registrydomain.TypeMCP,
		MCPTarget: &registrydomain.MCPTarget{
			Code: code, URL: url, Transport: registrydomain.MCPTransportStreamableHTTP,
		},
	}
}

func accessInstall(t *testing.T, gw ids.GatewayID, sub, code string) *installationdomain.Installation {
	t.Helper()
	row, err := installationdomain.New(gw, sub, code, sub, nil)
	if err != nil {
		t.Fatalf("install: %v", err)
	}
	return row
}

func accessPolicy(t *testing.T, gw ids.GatewayID, kind storeaccessdomain.PrincipalType, id, mode string) *storeaccessdomain.Policy {
	t.Helper()
	row, err := storeaccessdomain.NewPolicy(gw, kind, id, mode)
	if err != nil {
		t.Fatalf("policy: %v", err)
	}
	return row
}

func accessCtx(method identity.Method, sub, claim string, groups ...string) context.Context {
	claims := map[string]any{}
	if len(groups) > 0 {
		claims[identity.ClaimGroups] = groups
	}
	if claim != "" {
		claims[identity.ClaimStoreAccess] = claim
	}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{
		Subject: sub, Method: method, Claims: claims,
	})
	return appgateway.WithGateway(ctx, &gatewaydomain.Gateway{
		Metadata: gatewaydomain.WithStoreMode(nil, gatewaydomain.StoreModeCurated),
	})
}

func accessList(t *testing.T, d *RPCDispatcher, ctx context.Context, rc *appconsumer.RoutableConsumer) []string {
	t.Helper()
	listed, err := d.Dispatch(ctx, rc, "", "tools/list", nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	return toolNamesOf(t, listed)
}

func accessCall(d *RPCDispatcher, ctx context.Context, rc *appconsumer.RoutableConsumer, name string) (any, error) {
	params, err := json.Marshal(map[string]string{"name": name})
	if err != nil {
		return nil, err
	}
	return d.Dispatch(ctx, rc, "", "tools/call", params)
}

func accessServers(t *testing.T, d *RPCDispatcher, ctx context.Context, rc *appconsumer.RoutableConsumer) int {
	t.Helper()
	raw, err := d.Dispatch(ctx, rc, "", "tools/call", json.RawMessage(`{"name":"trustgate_list_tools"}`))
	if err != nil {
		t.Fatalf("trustgate_list_tools: %v", err)
	}
	body, ok := raw.(json.RawMessage)
	if !ok {
		t.Fatalf("server listing = %T", raw)
	}
	var decoded struct {
		StructuredContent struct {
			Total int `json:"total_servers"`
		} `json:"structuredContent"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("decode server listing: %v", err)
	}
	return decoded.StructuredContent.Total
}

func upstreamTools(names []string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if strings.HasPrefix(name, "trustgate_") {
			continue
		}
		out = append(out, name)
	}
	return out
}

func containsTool(names []string, part string) bool {
	for _, name := range names {
		if strings.Contains(name, part) {
			return true
		}
	}
	return false
}

func nameWith(t *testing.T, names []string, part string) string {
	t.Helper()
	for _, name := range names {
		if strings.Contains(name, part) {
			return name
		}
	}
	t.Fatalf("no tool containing %q in %v", part, names)
	return ""
}

func clearCalls(ups ...*fakeUpstream) {
	for _, up := range ups {
		up.lastCall = ""
	}
}

type accessInstalls struct {
	rows []*installationdomain.Installation
}

func (a *accessInstalls) ListByPrincipal(_ context.Context, _ ids.GatewayID, sub string) ([]*installationdomain.Installation, error) {
	out := make([]*installationdomain.Installation, 0)
	for _, row := range a.rows {
		if row != nil && row.PrincipalSub == sub {
			out = append(out, row)
		}
	}
	return out, nil
}

type accessRegistries struct {
	items []*registrydomain.Registry
}

func (a *accessRegistries) List(context.Context, registrydomain.ListFilter) ([]*registrydomain.Registry, int, error) {
	return a.items, len(a.items), nil
}

type accessGrants struct {
	items []*storeaccessdomain.Grant
}

func (a *accessGrants) ListByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.Grant, error) {
	return a.items, nil
}

type accessPolicies struct {
	items []*storeaccessdomain.Policy
}

func (a *accessPolicies) ListPoliciesByGateway(context.Context, ids.GatewayID) ([]*storeaccessdomain.Policy, error) {
	return a.items, nil
}

func resetDials(d *countingDialer) {
	d.mu.Lock()
	d.dials = map[string]int{}
	d.mu.Unlock()
}

func dialCount(d *countingDialer) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	n := 0
	for _, c := range d.dials {
		n += c
	}
	return n
}
