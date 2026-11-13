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

package secretstore

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
)

// Eligibility is which gateways may hold references on a plane. It follows
// who operates the planes, which the deployment states explicitly.
type Eligibility string

// Eligibility values.
const (
	// EligibilityHybrid admits only gateways served by a customer-run data
	// plane. It is the default, and what NeuralTrust's own planes run with.
	EligibilityHybrid Eligibility = "hybrid"
	// EligibilityAll admits every gateway. Only installs where the customer
	// runs every plane (self-hosted, central control plane) set it.
	EligibilityAll Eligibility = "all"
)

// ParseEligibility parses s, case-insensitively. Empty is EligibilityHybrid.
func ParseEligibility(s string) (Eligibility, error) {
	switch e := Eligibility(strings.ToLower(strings.TrimSpace(s))); e {
	case "":
		return EligibilityHybrid, nil
	case EligibilityHybrid, EligibilityAll:
		return e, nil
	default:
		return "", fmt.Errorf("%w: eligibility must be %q or %q", ErrInvalidStore, EligibilityHybrid, EligibilityAll)
	}
}

// Eligible reports whether gw may hold and resolve references under e: every
// gateway under EligibilityAll, otherwise only hybrid gateways. A nil gateway
// is never eligible.
func Eligible(e Eligibility, gw *gateway.Gateway) bool {
	if gw == nil {
		return false
	}
	if e == EligibilityAll {
		return true
	}
	return gw.Entitlements.IsHybridDataPlane()
}
