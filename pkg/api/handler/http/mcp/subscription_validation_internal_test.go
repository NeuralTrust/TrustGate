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
	"testing"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/require"
)

// allNotificationKinds is every kind a client could ask for, so a case that
// honours a subset proves the narrowing rather than the request.
func allNotificationKinds() appmcp.HonouredSet {
	return appmcp.NewHonouredSet(
		appmcp.NotificationToolsListChanged,
		appmcp.NotificationPromptsListChanged,
		appmcp.NotificationResourcesListChanged,
	)
}

func toolkitConsumer(toolkit consumerdomain.Toolkit) *appconsumer.RoutableConsumer {
	return &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID:  ids.New[ids.ConsumerKind](),
			MCP: &consumerdomain.MCPPolicy{Toolkit: toolkit},
		},
	}
}

// The honoured subset is the intersection of what was asked for with what
// discovery advertises, so a kind the toolkit hides is unhonourable however it
// was requested.
func TestHonouredSubsetIntersectsTheAdvertisedSurface(t *testing.T) {
	t.Parallel()
	registryID := ids.New[ids.RegistryKind]()
	cases := []struct {
		name      string
		requested appmcp.HonouredSet
		rc        *appconsumer.RoutableConsumer
		want      []appmcp.NotificationKind
	}{
		{
			name:      "a nil toolkit exposes every kind",
			requested: allNotificationKinds(),
			rc:        &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{}},
			want: []appmcp.NotificationKind{
				appmcp.NotificationToolsListChanged,
				appmcp.NotificationPromptsListChanged,
				appmcp.NotificationResourcesListChanged,
			},
		},
		{
			name:      "an explicit empty toolkit exposes none",
			requested: allNotificationKinds(),
			rc:        toolkitConsumer(consumerdomain.Toolkit{}),
		},
		{
			name:      "a prompts-only toolkit honours prompts alone",
			requested: allNotificationKinds(),
			rc: toolkitConsumer(consumerdomain.Toolkit{
				{RegistryID: registryID, Prompt: "summarize"},
			}),
			want: []appmcp.NotificationKind{appmcp.NotificationPromptsListChanged},
		},
		{
			name:      "a resources toolkit honours the list change, never a per-URI update",
			requested: allNotificationKinds(),
			rc: toolkitConsumer(consumerdomain.Toolkit{
				{RegistryID: registryID, Resource: "file:///*"},
			}),
			want: []appmcp.NotificationKind{appmcp.NotificationResourcesListChanged},
		},
		{
			name:      "a request narrower than the surface stays narrow",
			requested: appmcp.NewHonouredSet(appmcp.NotificationToolsListChanged),
			rc: toolkitConsumer(consumerdomain.Toolkit{
				{RegistryID: registryID, Tool: "search"},
				{RegistryID: registryID, Prompt: "summarize"},
			}),
			want: []appmcp.NotificationKind{appmcp.NotificationToolsListChanged},
		},
		{
			name:      "a kind the toolkit hides is refused",
			requested: appmcp.NewHonouredSet(appmcp.NotificationResourcesListChanged),
			rc: toolkitConsumer(consumerdomain.Toolkit{
				{RegistryID: registryID, Tool: "search"},
			}),
		},
		{
			name:      "an empty request honours nothing",
			requested: appmcp.NewHonouredSet(),
			rc:        &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{}},
		},
		{
			name:      "an absent consumer honours nothing",
			requested: allNotificationKinds(),
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			honoured := honouredSubset(tc.requested, tc.rc)
			require.Equal(t, tc.want, nonEmptyKinds(honoured.Kinds()))
			for _, kind := range honoured.Kinds() {
				require.True(t, tc.requested.Has(kind), "honoured %q was never requested", kind)
			}
		})
	}
}

func nonEmptyKinds(kinds []appmcp.NotificationKind) []appmcp.NotificationKind {
	if len(kinds) == 0 {
		return nil
	}
	return kinds
}
