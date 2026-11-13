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

package grpc

import (
	"strings"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
)

func TestSecretStoresHeartbeatRoundTripAndCaps(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	in := []secretstore.Status{{
		Name: "corp-vault", Type: secretstore.TypeHashiCorpVault, AllowedPaths: []string{"ai/"},
		Gateways: []ids.GatewayID{gwID}, State: secretstore.StateOK, CheckedAt: time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC),
	}}
	got := secretStoresFromProto(secretStoresToProto(in))
	if len(got) != 1 || got[0].Name != "corp-vault" || got[0].Gateways[0] != gwID || !got[0].CheckedAt.Equal(in[0].CheckedAt) {
		t.Fatalf("round trip = %+v", got)
	}

	var many []*snapshotpb.SecretStoreStatus
	for range 80 {
		many = append(many, &snapshotpb.SecretStoreStatus{Name: strings.Repeat("n", 1000), Gateways: []string{"not-a-uuid", gwID.String()}})
	}
	capped := secretStoresFromProto(many)
	if len(capped) != maxSecretStores || len(capped[0].Name) > maxHeartbeatField || len(capped[0].Gateways) != 1 {
		t.Fatalf("caps not applied: %d stores, name %d bytes, gateways %v", len(capped), len(capped[0].Name), capped[0].Gateways)
	}
}

func TestHeartbeatCarriesLiveSecretStores(t *testing.T) {
	t.Parallel()
	c := &Client{}
	if c.currentHeartbeat() != nil {
		t.Fatal("no heartbeat before SetHeartbeat")
	}
	c.heartbeat = &snapshotpb.Heartbeat{Version: "v1"}
	state := secretstore.StateOK
	c.SetSecretStoreReporter(func() []secretstore.Status {
		return []secretstore.Status{{Name: "s", State: state}}
	})
	if hb := c.currentHeartbeat(); !hb.GetAcceptsSecretRefs() || hb.GetSecretStores()[0].GetState() != "ok" {
		t.Fatalf("heartbeat = %v", hb)
	}
	state = secretstore.StateUnavailable
	if hb := c.currentHeartbeat(); hb.GetSecretStores()[0].GetState() != "unavailable" {
		t.Fatal("each heartbeat must read the stores again")
	}
	if c.heartbeat.GetSecretStores() != nil {
		t.Fatal("the base heartbeat must not be modified")
	}
}
