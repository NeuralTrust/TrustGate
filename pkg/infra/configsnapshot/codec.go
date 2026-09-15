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

package configsnapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	storeaccessdomain "github.com/NeuralTrust/TrustGate/pkg/domain/storeaccess"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	configsync "github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/sync"
	"google.golang.org/protobuf/proto"
)

type Codec struct{}

var _ configsync.SnapshotCodec[*readmodel.Snapshot] = Codec{}

func NewCodec() Codec { return Codec{} }

func (Codec) Encode(snapshot *readmodel.Snapshot) ([]byte, error) {
	if snapshot == nil {
		return nil, fmt.Errorf("configsnapshot: encode nil snapshot")
	}
	msg, err := toProto(snapshot.Data())
	if err != nil {
		return nil, err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("configsnapshot: marshal snapshot: %w", err)
	}
	return raw, nil
}

func (Codec) Decode(raw []byte) (*readmodel.Snapshot, error) {
	var msg snapshotpb.Snapshot
	if err := proto.Unmarshal(raw, &msg); err != nil {
		return nil, fmt.Errorf("configsnapshot: unmarshal snapshot: %w", err)
	}
	data, err := fromProto(&msg)
	if err != nil {
		return nil, err
	}
	return readmodel.Build(data), nil
}

func (Codec) Version(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func toProto(data readmodel.Data) (*snapshotpb.Snapshot, error) {
	msg := &snapshotpb.Snapshot{Version: data.Version}

	var err error
	if msg.Gateways, err = encodeJSON(data.Gateways, "gateway", func(_ int, blob []byte) *snapshotpb.Gateway { return &snapshotpb.Gateway{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.Consumers, err = encodeJSON(data.Consumers, "consumer", func(_ int, blob []byte) *snapshotpb.Consumer { return &snapshotpb.Consumer{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.Registries, err = encodeJSON(data.Registries, "registry", func(_ int, blob []byte) *snapshotpb.Registry { return &snapshotpb.Registry{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.Policies, err = encodeJSON(data.Policies, "policy", func(_ int, blob []byte) *snapshotpb.Policy { return &snapshotpb.Policy{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.Auths, err = encodeJSON(data.Auths, "auth", func(i int, blob []byte) *snapshotpb.Auth {
		return &snapshotpb.Auth{Json: blob, KeyHash: data.Auths[i].KeyHash}
	}); err != nil {
		return nil, err
	}
	if msg.Providers, err = encodeJSON(data.Providers, "provider", func(_ int, blob []byte) *snapshotpb.Provider { return &snapshotpb.Provider{Json: blob} }); err != nil {
		return nil, err
	}

	for i := range data.CatalogModels {
		blob, err := json.Marshal(&data.CatalogModels[i].Model)
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: marshal catalog model: %w", err)
		}
		msg.CatalogModels = append(msg.CatalogModels, &snapshotpb.CatalogModel{
			Json:         blob,
			ProviderCode: data.CatalogModels[i].ProviderCode,
		})
	}

	if msg.StoreGrants, err = encodeJSON(data.StoreGrants, "store grant", func(_ int, blob []byte) *snapshotpb.StoreGrant { return &snapshotpb.StoreGrant{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.StorePolicies, err = encodeJSON(data.StorePolicies, "store policy", func(_ int, blob []byte) *snapshotpb.StorePolicy { return &snapshotpb.StorePolicy{Json: blob} }); err != nil {
		return nil, err
	}
	for i := range data.PlaygroundTokenKeys {
		msg.PlaygroundTokenKeys = append(msg.PlaygroundTokenKeys, &snapshotpb.VerificationKey{
			Kid: data.PlaygroundTokenKeys[i].KID,
			Pem: data.PlaygroundTokenKeys[i].PEM,
		})
	}

	return msg, nil
}

func encodeJSON[T any, P any](items []T, entity string, wrap func(int, []byte) P) ([]P, error) {
	out := make([]P, 0, len(items))
	for i := range items {
		blob, err := json.Marshal(&items[i])
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: marshal %s: %w", entity, err)
		}
		out = append(out, wrap(i, blob))
	}
	return out, nil
}

func fromProto(msg *snapshotpb.Snapshot) (readmodel.Data, error) {
	data := readmodel.Data{Version: msg.GetVersion()}

	var err error
	if data.Gateways, err = decodeJSON[*snapshotpb.Gateway, gatewaydomain.Gateway](msg.GetGateways(), "gateway", func(m *snapshotpb.Gateway) []byte { return m.GetJson() }, func(_ *snapshotpb.Gateway, g *gatewaydomain.Gateway) {
		if strings.TrimSpace(g.Entitlements.Tier) == "" {
			g.Entitlements = gatewaydomain.DefaultEntitlements()
		}
	}); err != nil {
		return readmodel.Data{}, err
	}
	if data.Consumers, err = decodeJSON[*snapshotpb.Consumer, consumerdomain.Consumer](msg.GetConsumers(), "consumer", func(m *snapshotpb.Consumer) []byte { return m.GetJson() }, nil); err != nil {
		return readmodel.Data{}, err
	}
	if data.Registries, err = decodeJSON[*snapshotpb.Registry, registrydomain.Registry](msg.GetRegistries(), "registry", func(m *snapshotpb.Registry) []byte { return m.GetJson() }, nil); err != nil {
		return readmodel.Data{}, err
	}
	if data.Policies, err = decodeJSON[*snapshotpb.Policy, policydomain.Policy](msg.GetPolicies(), "policy", func(m *snapshotpb.Policy) []byte { return m.GetJson() }, nil); err != nil {
		return readmodel.Data{}, err
	}
	if data.Auths, err = decodeJSON[*snapshotpb.Auth, authdomain.Auth](msg.GetAuths(), "auth", func(m *snapshotpb.Auth) []byte { return m.GetJson() }, func(m *snapshotpb.Auth, a *authdomain.Auth) {
		// A snapshot published before the types were unified carries the
		// deprecated type; canonicalizing on read keeps a mixed-version fleet
		// from resolving the same auth differently per reader.
		a.Type = authdomain.NormalizeType(a.Type)
		a.KeyHash = m.GetKeyHash()
	}); err != nil {
		return readmodel.Data{}, err
	}
	if data.Providers, err = decodeJSON[*snapshotpb.Provider, catalogdomain.Provider](msg.GetProviders(), "provider", func(m *snapshotpb.Provider) []byte { return m.GetJson() }, nil); err != nil {
		return readmodel.Data{}, err
	}

	for _, m := range msg.GetCatalogModels() {
		var model catalogdomain.Model
		if err := json.Unmarshal(m.GetJson(), &model); err != nil {
			return readmodel.Data{}, fmt.Errorf("configsnapshot: unmarshal catalog model: %w", err)
		}
		data.CatalogModels = append(data.CatalogModels, readmodel.CatalogModel{
			ProviderCode: m.GetProviderCode(),
			Model:        model,
		})
	}

	if data.StoreGrants, err = decodeJSON[*snapshotpb.StoreGrant, storeaccessdomain.Grant](msg.GetStoreGrants(), "store grant", func(m *snapshotpb.StoreGrant) []byte { return m.GetJson() }, nil); err != nil {
		return readmodel.Data{}, err
	}
	if data.StorePolicies, err = decodeJSON[*snapshotpb.StorePolicy, storeaccessdomain.Policy](msg.GetStorePolicies(), "store policy", func(m *snapshotpb.StorePolicy) []byte { return m.GetJson() }, nil); err != nil {
		return readmodel.Data{}, err
	}
	for _, m := range msg.GetPlaygroundTokenKeys() {
		data.PlaygroundTokenKeys = append(data.PlaygroundTokenKeys, readmodel.VerificationKey{
			KID: m.GetKid(),
			PEM: m.GetPem(),
		})
	}

	return data, nil
}

func decodeJSON[M any, T any](messages []M, entity string, raw func(M) []byte, adjust func(M, *T)) ([]T, error) {
	out := make([]T, 0, len(messages))
	for _, message := range messages {
		var item T
		if err := json.Unmarshal(raw(message), &item); err != nil {
			return nil, fmt.Errorf("configsnapshot: unmarshal %s: %w", entity, err)
		}
		if adjust != nil {
			adjust(message, &item)
		}
		out = append(out, item)
	}
	return out, nil
}
