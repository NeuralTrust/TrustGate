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

	"github.com/NeuralTrust/TrustGate/pkg/configsnapshot/readmodel"
	"github.com/NeuralTrust/TrustGate/pkg/configsync"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
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

	for i := range data.Gateways {
		blob, err := json.Marshal(&data.Gateways[i])
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: marshal gateway: %w", err)
		}
		msg.Gateways = append(msg.Gateways, &snapshotpb.Gateway{Json: blob})
	}

	for i := range data.Consumers {
		blob, err := json.Marshal(&data.Consumers[i])
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: marshal consumer: %w", err)
		}
		msg.Consumers = append(msg.Consumers, &snapshotpb.Consumer{Json: blob})
	}

	for i := range data.Registries {
		blob, err := json.Marshal(&data.Registries[i])
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: marshal registry: %w", err)
		}
		msg.Registries = append(msg.Registries, &snapshotpb.Registry{Json: blob})
	}

	for i := range data.Policies {
		blob, err := json.Marshal(&data.Policies[i])
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: marshal policy: %w", err)
		}
		msg.Policies = append(msg.Policies, &snapshotpb.Policy{Json: blob})
	}

	for i := range data.Auths {
		blob, err := json.Marshal(&data.Auths[i])
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: marshal auth: %w", err)
		}
		msg.Auths = append(msg.Auths, &snapshotpb.Auth{Json: blob, KeyHash: data.Auths[i].KeyHash})
	}

	for i := range data.Roles {
		blob, err := json.Marshal(&data.Roles[i])
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: marshal role: %w", err)
		}
		msg.Roles = append(msg.Roles, &snapshotpb.Role{Json: blob})
	}

	for i := range data.Providers {
		blob, err := json.Marshal(&data.Providers[i])
		if err != nil {
			return nil, fmt.Errorf("configsnapshot: marshal provider: %w", err)
		}
		msg.Providers = append(msg.Providers, &snapshotpb.Provider{Json: blob})
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

	return msg, nil
}

func fromProto(msg *snapshotpb.Snapshot) (readmodel.Data, error) {
	data := readmodel.Data{Version: msg.GetVersion()}

	for _, m := range msg.GetGateways() {
		var g gatewaydomain.Gateway
		if err := json.Unmarshal(m.GetJson(), &g); err != nil {
			return readmodel.Data{}, fmt.Errorf("configsnapshot: unmarshal gateway: %w", err)
		}
		data.Gateways = append(data.Gateways, g)
	}

	for _, m := range msg.GetConsumers() {
		var c consumerdomain.Consumer
		if err := json.Unmarshal(m.GetJson(), &c); err != nil {
			return readmodel.Data{}, fmt.Errorf("configsnapshot: unmarshal consumer: %w", err)
		}
		data.Consumers = append(data.Consumers, c)
	}

	for _, m := range msg.GetRegistries() {
		var r registrydomain.Registry
		if err := json.Unmarshal(m.GetJson(), &r); err != nil {
			return readmodel.Data{}, fmt.Errorf("configsnapshot: unmarshal registry: %w", err)
		}
		data.Registries = append(data.Registries, r)
	}

	for _, m := range msg.GetPolicies() {
		var p policydomain.Policy
		if err := json.Unmarshal(m.GetJson(), &p); err != nil {
			return readmodel.Data{}, fmt.Errorf("configsnapshot: unmarshal policy: %w", err)
		}
		data.Policies = append(data.Policies, p)
	}

	for _, m := range msg.GetAuths() {
		var a authdomain.Auth
		if err := json.Unmarshal(m.GetJson(), &a); err != nil {
			return readmodel.Data{}, fmt.Errorf("configsnapshot: unmarshal auth: %w", err)
		}
		a.KeyHash = m.GetKeyHash()
		data.Auths = append(data.Auths, a)
	}

	for _, m := range msg.GetRoles() {
		var r roledomain.Role
		if err := json.Unmarshal(m.GetJson(), &r); err != nil {
			return readmodel.Data{}, fmt.Errorf("configsnapshot: unmarshal role: %w", err)
		}
		data.Roles = append(data.Roles, r)
	}

	for _, m := range msg.GetProviders() {
		var p catalogdomain.Provider
		if err := json.Unmarshal(m.GetJson(), &p); err != nil {
			return readmodel.Data{}, fmt.Errorf("configsnapshot: unmarshal provider: %w", err)
		}
		data.Providers = append(data.Providers, p)
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

	return data, nil
}
