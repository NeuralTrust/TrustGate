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

package gateway

import (
	"testing"
	"time"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

// fakeRow feeds scanGateway without a real database connection so the column
// order / entitlements unmarshal contract can be exercised as a unit test.
type fakeRow struct {
	id                                                     ids.GatewayID
	slug, status, domainName                               string
	metadata, telemetry, clientTLS, session, entitlements  []byte
	createdAt, updatedAt                                   time.Time
}

func (f *fakeRow) Scan(dest ...any) error {
	*dest[0].(*ids.GatewayID) = f.id
	*dest[1].(*string) = f.slug
	*dest[2].(*string) = f.status
	*dest[3].(*string) = f.domainName
	*dest[4].(*[]byte) = f.metadata
	*dest[5].(*[]byte) = f.telemetry
	*dest[6].(*[]byte) = f.clientTLS
	*dest[7].(*[]byte) = f.session
	*dest[8].(*[]byte) = f.entitlements
	*dest[9].(*time.Time) = f.createdAt
	*dest[10].(*time.Time) = f.updatedAt
	return nil
}

func TestScanGateway_UnmarshalsEntitlements(t *testing.T) {
	now := time.Now().UTC()
	row := &fakeRow{
		id:           ids.New[ids.GatewayKind](),
		slug:         "acme",
		status:       "active",
		entitlements: []byte(`{"tier":"standard"}`),
		createdAt:    now,
		updatedAt:    now,
	}

	g, err := scanGateway(row)
	if err != nil {
		t.Fatalf("scanGateway: %v", err)
	}
	if g.Entitlements.Tier != "standard" {
		t.Fatalf("Entitlements.Tier = %q, want standard", g.Entitlements.Tier)
	}
}

func TestScanGateway_DefaultsEntitlementsWhenColumnEmpty(t *testing.T) {
	now := time.Now().UTC()
	row := &fakeRow{
		id:        ids.New[ids.GatewayKind](),
		slug:      "acme",
		status:    "active",
		createdAt: now,
		updatedAt: now,
	}

	g, err := scanGateway(row)
	if err != nil {
		t.Fatalf("scanGateway: %v", err)
	}
	if g.Entitlements.Tier != domain.TierFree {
		t.Fatalf("Entitlements.Tier = %q, want default %q", g.Entitlements.Tier, domain.TierFree)
	}
}

func TestMarshalJSON_Entitlements_RoundTrips(t *testing.T) {
	want := domain.Entitlements{Tier: "enterprise"}
	raw, err := marshalJSON(want)
	if err != nil {
		t.Fatalf("marshalJSON: %v", err)
	}

	row := &fakeRow{
		id:           ids.New[ids.GatewayKind](),
		slug:         "acme",
		status:       "active",
		entitlements: raw,
		createdAt:    time.Now().UTC(),
		updatedAt:    time.Now().UTC(),
	}
	g, err := scanGateway(row)
	if err != nil {
		t.Fatalf("scanGateway: %v", err)
	}
	if g.Entitlements != want {
		t.Fatalf("Entitlements = %+v, want %+v", g.Entitlements, want)
	}
}
