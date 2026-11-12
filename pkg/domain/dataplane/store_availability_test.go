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

package dataplane_test

import (
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/dataplane"
	"github.com/stretchr/testify/assert"
)

func TestResolveStoreAvailability(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	live := func(version string) dataplane.Instance {
		return dataplane.Instance{State: "connected", LastSeen: now.Add(-30 * time.Second), Version: version}
	}
	cases := []struct {
		name      string
		instances []dataplane.Instance
		want      dataplane.StoreAvailability
	}{
		{
			name: "no instances",
			want: dataplane.StoreAvailability{Reason: dataplane.StoreNoDataPlane, MinVersion: dataplane.MinStoreVersion},
		},
		{
			name: "only stale or disconnected instances",
			instances: []dataplane.Instance{
				{State: "connected", LastSeen: now.Add(-dataplane.InstanceFreshness - time.Second), Version: "v0.99.0"},
				{State: "disconnected", LastSeen: now, Version: "v0.99.0"},
			},
			want: dataplane.StoreAvailability{Reason: dataplane.StoreNoDataPlane, MinVersion: dataplane.MinStoreVersion},
		},
		{
			name:      "every live instance recent enough",
			instances: []dataplane.Instance{live(dataplane.MinStoreVersion), live("0.99.1")},
			want:      dataplane.StoreAvailability{Available: true, Reason: dataplane.StoreAvailable, MinVersion: dataplane.MinStoreVersion},
		},
		{
			name: "stale old instance does not hold back a live new one",
			instances: []dataplane.Instance{
				live("v0.99.0"),
				{State: "connected", LastSeen: now.Add(-time.Hour), Version: "v0.70.0"},
			},
			want: dataplane.StoreAvailability{Available: true, Reason: dataplane.StoreAvailable, MinVersion: dataplane.MinStoreVersion},
		},
		{
			name:      "mixed rollout reports the lowest version",
			instances: []dataplane.Instance{live("v0.99.0"), live("v0.80.0"), live("0.77.2")},
			want:      dataplane.StoreAvailability{Reason: dataplane.StoreDataPlaneOutdated, MinVersion: dataplane.MinStoreVersion, LowestVersion: "v0.77.2"},
		},
		{
			name:      "pre-release of the minimum is outdated",
			instances: []dataplane.Instance{live(dataplane.MinStoreVersion + "-rc.1")},
			want:      dataplane.StoreAvailability{Reason: dataplane.StoreDataPlaneOutdated, MinVersion: dataplane.MinStoreVersion, LowestVersion: dataplane.MinStoreVersion + "-rc.1"},
		},
		{
			name:      "no heartbeat",
			instances: []dataplane.Instance{live("")},
			want:      dataplane.StoreAvailability{Reason: dataplane.StoreVersionUnknown, MinVersion: dataplane.MinStoreVersion},
		},
		{
			name:      "commit sha wins over an outdated version",
			instances: []dataplane.Instance{live("v0.80.0"), live("a8258d847")},
			want:      dataplane.StoreAvailability{Reason: dataplane.StoreVersionUnknown, MinVersion: dataplane.MinStoreVersion},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, dataplane.ResolveStoreAvailability(tc.instances, now))
		})
	}
}

func TestHostedStoreAvailability(t *testing.T) {
	t.Parallel()
	got := dataplane.HostedStoreAvailability()
	assert.True(t, got.Available)
	assert.Equal(t, dataplane.StoreAvailable, got.Reason)
}
