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

package modules

import (
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/infra/cache"
)

// Miss maps are only short-lived because they are created with their own TTL;
// one that fell back to the manager default would keep misses for minutes.
func TestInitializeMemoryCache_MissMapsKeepTheirShortTTL(t *testing.T) {
	t.Parallel()
	mgr := cache.NewTTLMapManager(time.Hour)
	initializeMemoryCache(mgr)

	for name, want := range map[string]time.Duration{
		cache.GatewayMissTTLName: cache.GatewayMissCacheTTL,
		cache.AuthKeyMissTTLName: cache.AuthKeyMissCacheTTL,
	} {
		if got := mgr.GetTTLMap(name).TTL(); got != want {
			t.Errorf("%s TTL = %s, want %s", name, got, want)
		}
	}
}
