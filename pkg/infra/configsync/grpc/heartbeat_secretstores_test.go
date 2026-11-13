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
	"reflect"
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
		AllowedDestinations: []string{"api.openai.com"},
	}, {Name: "open", Type: secretstore.TypeEnv, State: secretstore.StateOK}}
	got := secretStoresFromProto(secretStoresToProto(in))
	if len(got) != 2 || got[0].Name != "corp-vault" || got[0].Gateways[0] != gwID || !got[0].CheckedAt.Equal(in[0].CheckedAt) {
		t.Fatalf("round trip = %+v", got)
	}
	if len(got[0].AllowedDestinations) != 1 || got[0].AllowedDestinations[0] != "api.openai.com" || got[1].AllowedDestinations != nil {
		t.Fatalf("allowed destinations = %v / %v, want the list and an absent one", got[0].AllowedDestinations, got[1].AllowedDestinations)
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

func TestSecretRefsHeartbeatRoundTripAndCaps(t *testing.T) {
	t.Parallel()
	if refHealthToProto(secretstore.RefHealth{}) != nil {
		t.Fatal("a plane that resolved nothing sends no report")
	}
	gwID := ids.New[ids.GatewayKind]()
	in := secretstore.RefHealth{Total: 2, Unresolved: 1, Outcomes: []secretstore.RefOutcome{
		{GatewayID: gwID, Entity: "registry", ID: "r1", Field: "llm_target.auth.api_key.api_key", Reference: "secret://vault/ai/k", Store: "vault", Path: "ai/k", Class: secretstore.ClassNotFound},
		{GatewayID: gwID, Entity: "auth", ID: "a1", Field: "config.oauth2.client_secret", Store: "vault", Path: "ai/idp"},
	}}
	if got := refHealthFromProto(refHealthToProto(in)); !reflect.DeepEqual(got, in) {
		t.Fatalf("round trip = %+v", got)
	}
	big := &snapshotpb.SecretRefHealth{Total: 1000}
	for range secretstore.MaxRefOutcomes + 10 {
		big.Outcomes = append(big.Outcomes, &snapshotpb.SecretRefOutcome{GatewayId: gwID.String(), Field: strings.Repeat("f", 1000)})
	}
	big.Outcomes = append([]*snapshotpb.SecretRefOutcome{{GatewayId: "not-a-uuid"}}, big.Outcomes...)
	capped := refHealthFromProto(big)
	if len(capped.Outcomes) != secretstore.MaxRefOutcomes-1 || len(capped.Outcomes[0].Field) > maxHeartbeatField || capped.Total != 1000 {
		t.Fatalf("caps not applied: %d outcomes, field %d bytes", len(capped.Outcomes), len(capped.Outcomes[0].Field))
	}
}
