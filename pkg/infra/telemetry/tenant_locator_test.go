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

package telemetry_test

import (
	"testing"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
)

// A tenant must not be able to borrow an operator-only setting through the
// gateway's telemetry block, while the same settings stay valid for the operator
// who writes the defaults file.
func TestExporterLocator_TenantSettingsAreHeldToTheTenantPolicy(t *testing.T) {
	netguardtest.Deny(t)
	locator := newLocator()
	cfg := telemetrydomain.ExporterConfig{
		Name:     "postgres",
		Settings: map[string]any{"dsn_env": "DATABASE_URL"},
	}

	require.NoError(t, locator.Validate(cfg), "operator-written defaults may use dsn_env")
	require.ErrorContains(t, locator.ValidateTenant(cfg), "dsn_env is an operator setting")

	_, err := locator.BuildTenant(cfg)
	require.ErrorContains(t, err, "dsn_env is an operator setting")
}

func TestExporterLocator_TenantValidationStillRejectsUnknownExporters(t *testing.T) {
	netguardtest.Deny(t)
	locator := newLocator()
	cfg := telemetrydomain.ExporterConfig{Name: "nope"}
	require.ErrorContains(t, locator.ValidateTenant(cfg), "unknown exporter")
}
