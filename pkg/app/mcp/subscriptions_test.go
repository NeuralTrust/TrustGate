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
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestListChangedCapabilitiesUseExactTrio(t *testing.T) {
	t.Parallel()
	all := ListChangedCapabilities{Tools: true, Prompts: true, Resources: true}
	partial := ListChangedCapabilities{Tools: true, Resources: true}
	if all.Empty() {
		t.Fatal("all capabilities reported empty")
	}
	if !partial.Equal(ListChangedCapabilities{Tools: true, Resources: true}) {
		t.Fatal("equal capability trio did not compare equal")
	}
	if partial.Equal(all) {
		t.Fatal("different capability trio compared equal")
	}
	if got := all.Intersect(partial); !got.Equal(partial) {
		t.Fatalf("intersection = %+v, want %+v", got, partial)
	}
	honoured := partial.HonouredSet()
	if !honoured.Has(NotificationToolsListChanged) ||
		!honoured.Has(NotificationResourcesListChanged) ||
		honoured.Has(NotificationPromptsListChanged) {
		t.Fatalf("honoured set = %v", honoured.Kinds())
	}
}

func TestSubscriptionIdentityFormattingDoesNotExposeComponents(t *testing.T) {
	t.Parallel()
	const secret = "Bearer raw-secret-token"
	key := SubscriptionSourceKey{
		TargetDigest:          sha256.Sum256([]byte("https://upstream.example/private")),
		OriginDigest:          sha256.Sum256([]byte("https://upstream.example")),
		RegistryTargetDigest:  sha256.Sum256([]byte("registry-target")),
		PinDigest:             sha256.Sum256([]byte("pin")),
		CredentialFingerprint: sha256.Sum256([]byte(secret)),
		ProtocolVersion:       "2026-07-28",
		Capabilities:          ListChangedCapabilities{Tools: true},
	}
	values := []string{
		fmt.Sprint(key),
		fmt.Sprint(PreparedSubscription{Key: key, Capabilities: key.Capabilities}),
		fmt.Sprint(SubscriptionIdentity{
			GatewayID:            "gateway",
			ConsumerID:           "consumer",
			PrincipalFingerprint: secret,
			AuthID:               "auth",
			RegistryID:           "registry",
			RoleScopeFingerprint: "role",
		}),
	}
	for _, value := range values {
		if strings.Contains(value, secret) || strings.Contains(value, "upstream.example") {
			t.Fatalf("formatted value exposes source material: %q", value)
		}
	}
}

func TestSubscriptionSourceKeyEqualityIncludesProtocolAndTrio(t *testing.T) {
	t.Parallel()
	base := SubscriptionSourceKey{
		ProtocolVersion: "2026-07-28",
		Capabilities:    ListChangedCapabilities{Tools: true},
	}
	protocolChanged := base
	protocolChanged.ProtocolVersion = "2025-11-25"
	if protocolChanged == base {
		t.Fatal("protocol change did not alter source-key equality")
	}
	trioChanged := base
	trioChanged.Capabilities.Prompts = true
	if trioChanged == base {
		t.Fatal("capability change did not alter source-key equality")
	}
}

func TestBoundNotificationKind(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		raw        string
		wantKind   NotificationKind
		wantBound  bool
		wantMethod string
	}{
		{
			name:       "tools",
			raw:        "toolsListChanged",
			wantKind:   NotificationToolsListChanged,
			wantBound:  true,
			wantMethod: "notifications/tools/list_changed",
		},
		{
			name:       "prompts",
			raw:        "promptsListChanged",
			wantKind:   NotificationPromptsListChanged,
			wantBound:  true,
			wantMethod: "notifications/prompts/list_changed",
		},
		{
			name:       "resources",
			raw:        "resourcesListChanged",
			wantKind:   NotificationResourcesListChanged,
			wantBound:  true,
			wantMethod: "notifications/resources/list_changed",
		},
		{name: "unknown kind", raw: "resourcesUpdated"},
		{name: "empty string", raw: ""},
		{name: "wrong case", raw: "toolslistchanged"},
		{name: "notification method is not a kind", raw: "notifications/tools/list_changed"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kind, ok := BoundNotificationKind(tc.raw)
			if ok != tc.wantBound {
				t.Fatalf("bound = %t, want %t", ok, tc.wantBound)
			}
			if kind != tc.wantKind {
				t.Fatalf("kind = %q, want %q", kind, tc.wantKind)
			}
			if kind.Method() != tc.wantMethod {
				t.Fatalf("method = %q, want %q", kind.Method(), tc.wantMethod)
			}
		})
	}
}

func TestHonouredSetAlgebra(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		kinds     []NotificationKind
		intersect []NotificationKind
		want      []NotificationKind
		wantEmpty bool
	}{
		{name: "empty set", wantEmpty: true},
		{
			name:  "declaration order does not leak into Kinds",
			kinds: []NotificationKind{NotificationResourcesListChanged, NotificationToolsListChanged},
			want:  []NotificationKind{NotificationToolsListChanged, NotificationResourcesListChanged},
		},
		{
			name:  "duplicates collapse",
			kinds: []NotificationKind{NotificationToolsListChanged, NotificationToolsListChanged},
			want:  []NotificationKind{NotificationToolsListChanged},
		},
		{
			name:      "unknown kinds are never admitted",
			kinds:     []NotificationKind{NotificationToolsListChanged, NotificationKind("resourcesUpdated")},
			want:      []NotificationKind{NotificationToolsListChanged},
			wantEmpty: false,
		},
		{
			name:      "intersection narrows",
			kinds:     []NotificationKind{NotificationToolsListChanged, NotificationPromptsListChanged},
			intersect: []NotificationKind{NotificationPromptsListChanged, NotificationResourcesListChanged},
			want:      []NotificationKind{NotificationPromptsListChanged},
		},
		{
			name:      "intersection with nothing honours nothing",
			kinds:     []NotificationKind{NotificationToolsListChanged},
			intersect: []NotificationKind{},
			want:      []NotificationKind{},
			wantEmpty: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			set := NewHonouredSet(tc.kinds...)
			if tc.intersect != nil {
				set = set.Intersect(NewHonouredSet(tc.intersect...))
			}
			if set.Empty() != tc.wantEmpty {
				t.Fatalf("Empty = %t, want %t", set.Empty(), tc.wantEmpty)
			}
			got := set.Kinds()
			if len(got) != len(tc.want) {
				t.Fatalf("Kinds = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("Kinds = %v, want %v", got, tc.want)
				}
			}
			for _, kind := range tc.want {
				if !set.Has(kind) {
					t.Fatalf("Has(%q) = false, want true", kind)
				}
			}
		})
	}
}

func TestNewIsolationKey(t *testing.T) {
	t.Parallel()
	gatewayID := ids.New[ids.GatewayKind]().String()
	consumerID := ids.New[ids.ConsumerKind]()
	rc := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{ID: consumerID}}
	ctx := identity.WithPrincipal(context.Background(), &identity.Principal{Issuer: "iss", Subject: "sub"})

	key := NewIsolationKey(ctx, gatewayID, rc)
	if key.GatewayID != gatewayID {
		t.Errorf("GatewayID = %q, want %q", key.GatewayID, gatewayID)
	}
	if key.ConsumerID != consumerID.String() {
		t.Errorf("ConsumerID = %q, want %q", key.ConsumerID, consumerID)
	}
	if len(key.Principal) != 64 {
		t.Errorf("Principal = %q, want the full sha256 hex digest", key.Principal)
	}
	if key.RoleScope != SurfaceConfigFingerprint(rc) {
		t.Errorf("RoleScope = %q, want the surface config fingerprint", key.RoleScope)
	}

	t.Run("every component separates streams", func(t *testing.T) {
		t.Parallel()
		otherPrincipal := identity.WithPrincipal(
			context.Background(),
			&identity.Principal{Issuer: "iss", Subject: "other"},
		)
		otherConsumer := &appconsumer.RoutableConsumer{
			Consumer: &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind]()},
		}
		otherScope := &appconsumer.RoutableConsumer{
			Consumer: &consumerdomain.Consumer{
				ID:  consumerID,
				MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{}},
			},
		}
		cases := map[string]IsolationKey{
			"gateway":   NewIsolationKey(ctx, ids.New[ids.GatewayKind]().String(), rc),
			"consumer":  NewIsolationKey(ctx, gatewayID, otherConsumer),
			"principal": NewIsolationKey(otherPrincipal, gatewayID, rc),
			"scope":     NewIsolationKey(ctx, gatewayID, otherScope),
		}
		for name, other := range cases {
			if other == key {
				t.Errorf("a different %s must produce a different isolation key", name)
			}
		}
	})

	t.Run("no principal and no consumer are representable", func(t *testing.T) {
		t.Parallel()
		bare := NewIsolationKey(context.Background(), gatewayID, nil)
		if bare.Principal != "" || bare.ConsumerID != "" {
			t.Errorf("bare key = %+v, want empty principal and consumer", bare)
		}
		if bare.RoleScope != "0" {
			t.Errorf("RoleScope = %q, want the nil-consumer sentinel", bare.RoleScope)
		}
	})

	t.Run("auth id isolates a caller without an OIDC principal", func(t *testing.T) {
		t.Parallel()
		firstAuth := ids.New[ids.AuthKind]()
		secondAuth := ids.New[ids.AuthKind]()
		first := NewIsolationKey(appconsumer.WithAuthID(context.Background(), firstAuth), gatewayID, rc)
		second := NewIsolationKey(appconsumer.WithAuthID(context.Background(), secondAuth), gatewayID, rc)
		if first.Principal != "auth:"+firstAuth.String() {
			t.Fatalf("Principal = %q, want auth bucket", first.Principal)
		}
		if first.Principal == second.Principal {
			t.Fatal("distinct auth IDs collapsed into one principal bucket")
		}
	})
}

func expectedSurfaceFingerprint(rc *appconsumer.RoutableConsumer) string {
	if rc == nil || rc.Consumer == nil {
		return "0"
	}
	parts := make([]string, 0, len(rc.Registries))
	for _, reg := range rc.Registries {
		if reg == nil || !reg.IsMCP() {
			continue
		}
		parts = append(parts, reg.ID.String()+"@"+reg.UpdatedAt.UTC().Format(time.RFC3339Nano))
	}
	toolkit := rc.Consumer.Toolkit()
	entries := make([]string, 0, len(toolkit)+1)
	if toolkit == nil {
		entries = append(entries, "tk-state:nil")
	} else {
		entries = append(entries, "tk-state:configured")
	}
	for _, e := range toolkit {
		entries = append(entries, "tk:"+e.RegistryID.String()+"/"+e.Tool+"/"+e.Prompt+"/"+e.Resource+"/"+e.ExposeAs)
	}
	sort.Strings(parts)
	sort.Strings(entries)
	sum := sha256.Sum256([]byte(strings.Join(append(parts, entries...), "|")))
	return hex.EncodeToString(sum[:surfaceConfigDigestBytes])
}

func TestSurfaceConfigFingerprintMatchesCanonicalAlgorithm(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	updatedAt := time.Date(2026, 8, 18, 10, 30, 0, 0, time.UTC)
	mcpRegistry := &registrydomain.Registry{
		ID:        registryID,
		Type:      registrydomain.TypeMCP,
		UpdatedAt: updatedAt,
	}
	llmRegistry := &registrydomain.Registry{
		ID:        ids.New[ids.RegistryKind](),
		Type:      registrydomain.TypeLLM,
		UpdatedAt: updatedAt,
	}
	consumerID := ids.New[ids.ConsumerKind]()

	tests := []struct {
		name string
		rc   *appconsumer.RoutableConsumer
	}{
		{name: "nil routable consumer"},
		{name: "nil consumer", rc: &appconsumer.RoutableConsumer{}},
		{
			name: "nil toolkit",
			rc:   &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{ID: consumerID}},
		},
		{
			name: "empty toolkit",
			rc: &appconsumer.RoutableConsumer{
				Consumer: &consumerdomain.Consumer{
					ID:  consumerID,
					MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{}},
				},
			},
		},
		{
			name: "registries including a nil and a non-MCP entry",
			rc: &appconsumer.RoutableConsumer{
				Consumer:   &consumerdomain.Consumer{ID: consumerID},
				Registries: []*registrydomain.Registry{mcpRegistry, nil, llmRegistry},
			},
		},
		{
			name: "configured toolkit",
			rc: &appconsumer.RoutableConsumer{
				Consumer: &consumerdomain.Consumer{
					ID: consumerID,
					MCP: &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
						{RegistryID: registryID, Tool: "search", ExposeAs: "find"},
						{RegistryID: registryID, Resource: "doc://a"},
					}},
				},
				Registries: []*registrydomain.Registry{mcpRegistry},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			want := expectedSurfaceFingerprint(tc.rc)
			if got := SurfaceConfigFingerprint(tc.rc); got != want {
				t.Fatalf("SurfaceConfigFingerprint = %q, want %q", got, want)
			}
		})
	}
}

func TestSurfaceConfigFingerprintChangesWithConfiguration(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	base := func(updatedAt time.Time, toolkit consumerdomain.Toolkit) *appconsumer.RoutableConsumer {
		return &appconsumer.RoutableConsumer{
			Consumer: &consumerdomain.Consumer{
				ID:  consumerID,
				MCP: &consumerdomain.MCPPolicy{Toolkit: toolkit},
			},
			Registries: []*registrydomain.Registry{{
				ID:        registryID,
				Type:      registrydomain.TypeMCP,
				UpdatedAt: updatedAt,
			}},
		}
	}
	at := time.Date(2026, 8, 18, 10, 30, 0, 0, time.UTC)
	toolkit := consumerdomain.Toolkit{{RegistryID: registryID, Tool: "search"}}

	reference := SurfaceConfigFingerprint(base(at, toolkit))
	if same := SurfaceConfigFingerprint(base(at, toolkit)); same != reference {
		t.Fatalf("fingerprint is not stable: %q then %q", reference, same)
	}
	if touched := SurfaceConfigFingerprint(base(at.Add(time.Nanosecond), toolkit)); touched == reference {
		t.Error("a registry update must change the fingerprint")
	}
	narrowed := consumerdomain.Toolkit{{RegistryID: registryID, Tool: "search", ExposeAs: "find"}}
	if got := SurfaceConfigFingerprint(base(at, narrowed)); got == reference {
		t.Error("a toolkit change must change the fingerprint")
	}
}
