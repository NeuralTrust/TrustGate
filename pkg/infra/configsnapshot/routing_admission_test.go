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

package configsnapshot_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	"github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func canonicalRoutingData(escape bool) readmodel.Data {
	gw := ids.New[ids.GatewayKind]()
	reg := ids.New[ids.RegistryKind]()
	return readmodel.Data{
		Registries: []registrydomain.Registry{{ID: reg, GatewayID: gw}},
		Consumers: []consumerdomain.Consumer{{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Active: true,
			RegistryIDs:   []ids.RegistryID{reg},
			ModelPolicies: consumerdomain.ModelPolicies{reg: {Allowed: []string{"low", "mid", "high"}}},
			LBConfig: &consumerdomain.LBConfig{
				Enabled: true, Algorithm: algorithm.SmartRouting,
				Members: []consumerdomain.LBPoolMember{{RegistryID: reg, Model: "low"}, {RegistryID: reg, Model: "mid"}, {RegistryID: reg, Model: "high"}},
				SmartRouting: &registrydomain.SmartRoutingConfig{
					SR1: &registrydomain.SR1Config{CacheTTLSeconds: 300, EscapeHatchEnabled: escape},
					Tiers: []registrydomain.SmartRoutingTier{
						{RegistryID: reg, Model: "high", MinScore: .45},
						{RegistryID: reg, Model: "low", MinScore: 0},
						{RegistryID: reg, Model: "mid", MinScore: .187},
					},
				},
			},
		}},
	}
}

// Build the historical wire directly; production Encode intentionally cannot
// emit it. The input begins with a fully valid pool and snapshot references.
func historicalRoutingRaw(t *testing.T, data readmodel.Data, mutate func(map[string]any)) []byte {
	t.Helper()
	raw, err := configsnapshot.NewCodec().Encode(readmodel.Build(data))
	require.NoError(t, err)
	var message snapshotpb.Snapshot
	require.NoError(t, proto.Unmarshal(raw, &message))
	var consumer map[string]any
	require.NoError(t, json.Unmarshal(message.Consumers[0].Json, &consumer))
	mutate(consumer)
	message.Consumers[0].Json, err = json.Marshal(consumer)
	require.NoError(t, err)
	raw, err = proto.MarshalOptions{Deterministic: true}.Marshal(&message)
	require.NoError(t, err)
	return raw
}

func smartWire(consumer map[string]any) map[string]any {
	return consumer["lb_config"].(map[string]any)["smart_routing"].(map[string]any)
}

func settingsWire(consumer map[string]any) map[string]any {
	return smartWire(consumer)["sr1"].(map[string]any)
}

func TestCodecRejectsHistoricalRoutingSettings(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"legacy envelope", func(c map[string]any) { delete(smartWire(c), "sr1") }},
		{"omitted escape", func(c map[string]any) { delete(settingsWire(c), "escape_hatch_enabled") }},
		{"null escape", func(c map[string]any) { settingsWire(c)["escape_hatch_enabled"] = nil }},
		{"nonboolean escape", func(c map[string]any) { settingsWire(c)["escape_hatch_enabled"] = "false" }},
		{"omitted TTL", func(c map[string]any) { delete(settingsWire(c), "cache_ttl_seconds") }},
		{"null TTL", func(c map[string]any) { settingsWire(c)["cache_ttl_seconds"] = nil }},
		{"zero TTL", func(c map[string]any) { settingsWire(c)["cache_ttl_seconds"] = 0 }},
		{"excessive TTL", func(c map[string]any) { settingsWire(c)["cache_ttl_seconds"] = 86401 }},
		{"fractional TTL", func(c map[string]any) { settingsWire(c)["cache_ttl_seconds"] = 1.5 }},
		{"legacy cuts", func(c map[string]any) { smartWire(c)["tiers"].([]any)[0].(map[string]any)["min_score"] = .8 }},
		{"unpinned model", func(c map[string]any) { delete(smartWire(c)["tiers"].([]any)[0].(map[string]any), "model") }},
		{"undeclared route", func(c map[string]any) { smartWire(c)["tiers"].([]any)[0].(map[string]any)["model"] = "outside" }},
		{"unbound registry", func(c map[string]any) { c["registry_ids"] = []any{} }},
		{"missing policies", func(c map[string]any) { delete(c, "model_policies") }},
		{"wrong algorithm", func(c map[string]any) { c["lb_config"].(map[string]any)["algorithm"] = algorithm.RoundRobin }},
	}
	for _, tc := range cases {
		for _, enabled := range []bool{true, false} {
			t.Run(tc.name+map[bool]string{true: "/active", false: "/disabled"}[enabled], func(t *testing.T) {
				t.Parallel()
				data := canonicalRoutingData(true)
				data.Consumers[0].Active, data.Consumers[0].LBConfig.Enabled = enabled, enabled
				raw := historicalRoutingRaw(t, data, tc.mutate)
				_, err := configsnapshot.NewCodec().Decode(raw)
				require.Error(t, err)
			})
		}
	}
}

func TestCodecRoutingPreservesExplicitPreferences(t *testing.T) {
	t.Parallel()
	for _, escape := range []bool{false, true} {
		data := canonicalRoutingData(escape)
		data.Consumers[0].Active, data.Consumers[0].LBConfig.Enabled = false, false
		codec := configsnapshot.NewCodec()
		raw, err := codec.Encode(readmodel.Build(data))
		require.NoError(t, err)
		decoded, err := codec.Decode(raw)
		require.NoError(t, err)
		assert.Equal(t, data.Consumers[0].LBConfig, decoded.Data().Consumers[0].LBConfig)
		assert.False(t, decoded.Data().Consumers[0].Active)
		reraw, err := codec.Encode(decoded)
		require.NoError(t, err)
		assert.Equal(t, raw, reraw, "admission cannot normalize order or settings")
	}
}

func TestCodecRoutingRejectsWrongGatewayReference(t *testing.T) {
	t.Parallel()
	data := canonicalRoutingData(false)
	codec := configsnapshot.NewCodec()
	raw, err := codec.Encode(readmodel.Build(data))
	require.NoError(t, err)
	data.Registries[0].GatewayID = ids.New[ids.GatewayKind]()
	_, err = codec.Encode(readmodel.Build(data))
	require.Error(t, err, "producer compilation must reject the wrong owner")
	var message snapshotpb.Snapshot
	require.NoError(t, proto.Unmarshal(raw, &message))
	message.Registries[0].Json, err = json.Marshal(data.Registries[0])
	require.NoError(t, err)
	raw, err = proto.Marshal(&message)
	require.NoError(t, err)
	_, err = codec.Decode(raw)
	require.Error(t, err, "historical wire must also fail the owner check")
}

type routingFetcher struct {
	raw []byte
	err error
}

func (f *routingFetcher) Fetch(context.Context, string) ([]byte, string, bool, error) {
	return f.raw, configsnapshot.NewCodec().Version(f.raw), false, f.err
}

type routingTransport struct{ acks []string }

func (t *routingTransport) Watch(ctx context.Context) (string, error) {
	<-ctx.Done()
	return "", ctx.Err()
}

func (t *routingTransport) Ack(_ context.Context, version string) error {
	t.acks = append(t.acks, version)
	return nil
}

func routingLKG(t *testing.T) *configsync.LKGStore[*readmodel.Snapshot] {
	t.Helper()
	crypto, err := configsync.NewAESGCMCrypto(make([]byte, 32))
	require.NoError(t, err)
	return configsync.NewLKGStore[*readmodel.Snapshot](crypto, configsnapshot.NewCodec(), filepath.Join(t.TempDir(), "snapshot.lkg"))
}

func TestWorkerRoutingAdmissionKeepsLastCompatibleSnapshot(t *testing.T) {
	t.Parallel()
	codec := configsnapshot.NewCodec()
	data := canonicalRoutingData(true)
	good, err := codec.Encode(readmodel.Build(data))
	require.NoError(t, err)
	bad := historicalRoutingRaw(t, data, func(c map[string]any) { delete(settingsWire(c), "escape_hatch_enabled") })
	store := configsync.NewMemoryStore[*readmodel.Snapshot]()
	transport := &routingTransport{}
	fetcher := &routingFetcher{raw: bad}
	lkg := routingLKG(t)
	worker := configsync.NewWorker[*readmodel.Snapshot](fetcher, store, transport, lkg, codec, nil, configsync.WorkerConfig{})
	require.Error(t, worker.Converge(context.Background()))
	assert.ErrorIs(t, configsync.ReadinessCheck(store)(context.Background()), configsync.ErrNotReady)
	assert.Equal(t, configsync.SnapshotNone, worker.Status().Info().State)
	assert.Empty(t, transport.acks)
	fetcher.raw = good
	require.NoError(t, worker.Converge(context.Background()))
	fetcher.raw = bad
	require.Error(t, worker.Converge(context.Background()))
	retained, ok := store.Load()
	require.True(t, ok)
	assert.Equal(t, good, retained.Raw)
	assert.Equal(t, codec.Version(good), retained.Version)
	assert.Equal(t, []string{retained.Version}, transport.acks)
	assert.NoError(t, configsync.ReadinessCheck(store)(context.Background()))
	saved, err := lkg.Load()
	require.NoError(t, err)
	require.NotNil(t, saved)
	assert.Equal(t, good, saved.Raw, "rejected live payload must not replace encrypted LKG")
}

func TestWorkerRoutingLKGAdmissionDuringControlPlaneOutage(t *testing.T) {
	t.Parallel()
	for _, compatible := range []bool{false, true} {
		t.Run(map[bool]string{false: "reject historical", true: "recover canonical"}[compatible], func(t *testing.T) {
			t.Parallel()
			codec := configsnapshot.NewCodec()
			data := canonicalRoutingData(false)
			raw, err := codec.Encode(readmodel.Build(data))
			require.NoError(t, err)
			if !compatible {
				raw = historicalRoutingRaw(t, data, func(c map[string]any) {
					c["active"] = false
					c["lb_config"].(map[string]any)["enabled"] = false
					delete(settingsWire(c), "escape_hatch_enabled")
				})
			}
			lkg := routingLKG(t)
			require.NoError(t, lkg.Persist(&configsync.Versioned[*readmodel.Snapshot]{Raw: raw, Version: codec.Version(raw)}))
			store := configsync.NewMemoryStore[*readmodel.Snapshot]()
			worker := configsync.NewWorker[*readmodel.Snapshot](&routingFetcher{err: errors.New("control plane unavailable")}, store, &routingTransport{}, lkg, codec, nil, configsync.WorkerConfig{})
			// Restore occurs before convergence, even if startup is cancelled.
			// Both watch loops then terminate without any sleeps or network calls.
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			require.ErrorIs(t, worker.Run(ctx), context.Canceled)
			if !compatible {
				assert.ErrorIs(t, configsync.ReadinessCheck(store)(context.Background()), configsync.ErrNotReady)
				assert.Equal(t, configsync.SnapshotNone, worker.Status().Info().State)
				return
			}
			assert.NoError(t, configsync.ReadinessCheck(store)(context.Background()))
			assert.Equal(t, configsync.SnapshotLKG, worker.Status().Info().State)
			retained, ok := store.Load()
			require.True(t, ok)
			assert.Equal(t, raw, retained.Raw)
		})
	}
}
