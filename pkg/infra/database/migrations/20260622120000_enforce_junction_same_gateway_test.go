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

package migrations

import (
	"strings"
	"testing"
)

func TestEnforceJunctionSameGatewayCoversEveryJunction(t *testing.T) {
	t.Parallel()

	junctions := []string{
		"consumer_registry",
		"consumer_role",
		"consumer_auth",
		"consumer_policy",
		"role_registry",
	}
	for _, table := range junctions {
		if !strings.Contains(enforceJunctionSameGatewayDDL, "BEFORE INSERT ON "+table) {
			t.Fatalf("missing BEFORE INSERT trigger for junction table %q", table)
		}
		if !strings.Contains(dropJunctionSameGatewayDDL, table+"_gateway_guard") {
			t.Fatalf("down migration must drop the trigger for %q", table)
		}
	}
}

func TestEnforceJunctionSameGatewayRejectsCrossGateway(t *testing.T) {
	t.Parallel()

	if !strings.Contains(enforceJunctionSameGatewayDDL, "left_gw IS NOT NULL AND right_gw IS NOT NULL AND left_gw <> right_gw") {
		t.Fatal("trigger must reject links whose gateways differ")
	}
	if !strings.Contains(enforceJunctionSameGatewayDDL, "ERRCODE = 'AG422'") {
		t.Fatal("trigger must raise the AG422 cross-gateway error code")
	}
}
