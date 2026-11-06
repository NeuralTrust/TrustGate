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
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"time"

	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	ratelimitdomain "github.com/NeuralTrust/TrustGate/pkg/domain/ratelimit"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/routing/algorithm"
	snapshotpb "github.com/NeuralTrust/TrustGate/pkg/infra/configsnapshot/proto"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"google.golang.org/protobuf/proto"
)

// This file freezes the snapshot encoder and the full-compile assembly as they
// were before fragment assembly existed. It is the oracle the fragment encoder
// is held to: production code may change, these copies must not, so a test
// that compares against them proves "the bytes a data plane receives did not
// change" rather than "two new code paths agree with each other".

func legacyEncode(data readmodel.Data) ([]byte, error) {
	msg, err := legacyToProto(readmodel.Build(data).Data())
	if err != nil {
		return nil, err
	}
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("configsnapshot: marshal snapshot: %w", err)
	}
	return raw, nil
}

// compileInput is what a full compile reads: the gateways in listing order,
// each gateway's collected data (nil when its persisted config is corrupt),
// and the inputs shared by every flavor.
type compileInput struct {
	gateways    []gatewaydomain.Gateway
	data        map[ids.GatewayID]*readmodel.Data
	caps        map[string]ratelimitdomain.TenantCaps
	revocations []readmodel.SessionRevocation
	playground  []readmodel.VerificationKey
	usage       bool
	catalog     readmodel.Data
}

// served is the tenant part of the global snapshot and of every scope, and
// the catalog part appended to each of them.
type served struct {
	global  []byte
	scoped  map[string][]byte
	catalog []byte
}

// legacyCompile reproduces CompileAll's assembly followed by the dispatcher's
// encode of each flavor.
func legacyCompile(in compileInput) (served, error) {
	global := readmodel.Data{}
	buckets := map[string]*readmodel.Data{}
	for i := range in.gateways {
		collected := in.data[in.gateways[i].ID]
		if collected == nil {
			continue
		}
		if !in.gateways[i].ServedByOwnDataPlane() {
			legacyAppendGatewayData(&global, in.gateways[i], *collected)
		}
		scope := in.gateways[i].ID.String()
		bucket, ok := buckets[scope]
		if !ok {
			bucket = &readmodel.Data{}
			buckets[scope] = bucket
		}
		legacyAppendGatewayData(bucket, in.gateways[i], *collected)
	}
	global.PlaygroundTokenKeys = slices.Clone(in.playground)
	for _, bucket := range buckets {
		bucket.PlaygroundTokenKeys = slices.Clone(in.playground)
	}
	legacyStampTenantCaps(&global, in.caps)
	legacyStampSessionRevocations(&global, in.revocations)
	global.UsageEnforcement = in.usage
	for _, bucket := range buckets {
		legacyStampTenantCaps(bucket, in.caps)
		legacyStampSessionRevocations(bucket, in.revocations)
		bucket.UsageEnforcement = in.usage
	}
	catData := readmodel.Data{}
	legacyMergeCatalog(&catData, in.catalog)
	legacySortData(&catData)
	legacySortData(&global)

	var out served
	var err error
	if out.catalog, err = legacyEncode(catData); err != nil {
		return served{}, err
	}
	if out.global, err = legacyEncode(global); err != nil {
		return served{}, err
	}
	out.scoped = make(map[string][]byte, len(buckets))
	for scope, bucket := range buckets {
		legacySortData(bucket)
		if out.scoped[scope], err = legacyEncode(*bucket); err != nil {
			return served{}, err
		}
	}
	return out, nil
}

func legacyToProto(data readmodel.Data) (*snapshotpb.Snapshot, error) {
	msg := &snapshotpb.Snapshot{Version: data.Version}
	owners := legacyRegistryOwners(data.Registries)
	consumers := legacyAdmitConsumers(data.Consumers, admissionEncode, func(i int) error {
		return legacyValidateConsumerSmartRouting(&data.Consumers[i], owners)
	})

	var err error
	if msg.Gateways, err = legacyEncodeJSON(data.Gateways, "gateway", func(_ int, blob []byte) *snapshotpb.Gateway { return &snapshotpb.Gateway{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.Consumers, err = legacyEncodeJSON(consumers, "consumer", func(_ int, blob []byte) *snapshotpb.Consumer { return &snapshotpb.Consumer{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.Registries, err = legacyEncodeJSON(data.Registries, "registry", func(_ int, blob []byte) *snapshotpb.Registry { return &snapshotpb.Registry{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.Policies, err = legacyEncodeJSON(data.Policies, "policy", func(_ int, blob []byte) *snapshotpb.Policy { return &snapshotpb.Policy{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.Auths, err = legacyEncodeJSON(data.Auths, "auth", func(i int, blob []byte) *snapshotpb.Auth {
		return &snapshotpb.Auth{Json: blob, KeyHash: data.Auths[i].KeyHash}
	}); err != nil {
		return nil, err
	}
	if msg.Providers, err = legacyEncodeJSON(data.Providers, "provider", func(_ int, blob []byte) *snapshotpb.Provider { return &snapshotpb.Provider{Json: blob} }); err != nil {
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

	if msg.StoreGrants, err = legacyEncodeJSON(data.StoreGrants, "store grant", func(_ int, blob []byte) *snapshotpb.StoreGrant { return &snapshotpb.StoreGrant{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.StorePolicies, err = legacyEncodeJSON(data.StorePolicies, "store policy", func(_ int, blob []byte) *snapshotpb.StorePolicy { return &snapshotpb.StorePolicy{Json: blob} }); err != nil {
		return nil, err
	}
	if msg.StoreEveryone, err = legacyEncodeJSON(data.StoreEveryone, "store everyone", func(_ int, blob []byte) *snapshotpb.StoreEveryone { return &snapshotpb.StoreEveryone{Json: blob} }); err != nil {
		return nil, err
	}
	for i := range data.PlaygroundTokenKeys {
		msg.PlaygroundTokenKeys = append(msg.PlaygroundTokenKeys, &snapshotpb.VerificationKey{
			Kid: data.PlaygroundTokenKeys[i].KID,
			Pem: data.PlaygroundTokenKeys[i].PEM,
		})
	}

	msg.UsageEnforcement = data.UsageEnforcement

	msg.TenantCaps = make([]*snapshotpb.TenantCaps, 0, len(data.TenantCaps))
	for i := range data.TenantCaps {
		c := &data.TenantCaps[i]
		msg.TenantCaps = append(msg.TenantCaps, &snapshotpb.TenantCaps{
			TenantId:      c.TenantID,
			Tier:          c.Tier,
			BurstPerMin:   int32(c.BurstPerMin),   // #nosec G115 -- validated to ratelimit.MaxCap (int32) where the plan is stamped
			QuotaPerMonth: int32(c.QuotaPerMonth), // #nosec G115 -- validated to ratelimit.MaxCap (int32) where the plan is stamped
			MaxInstances:  int32(c.MaxInstances),  // #nosec G115 -- validated to ratelimit.MaxCap (int32) where the plan is stamped
		})
	}

	if msg.KeyGroupBudgets, err = legacyEncodeJSON(data.KeyGroupBudgets, "key group budget", func(_ int, blob []byte) *snapshotpb.KeyGroupBudget {
		return &snapshotpb.KeyGroupBudget{Json: blob}
	}); err != nil {
		return nil, err
	}

	msg.SessionRevocations = make([]*snapshotpb.SessionRevocation, 0, len(data.SessionRevocations))
	for i := range data.SessionRevocations {
		rev := data.SessionRevocations[i]
		msg.SessionRevocations = append(msg.SessionRevocations, &snapshotpb.SessionRevocation{
			GatewayId: rev.GatewayID,
			Org:       rev.Org,
			Subject:   rev.Subject,
			RevokedAt: rev.RevokedAt.UTC().Format(time.RFC3339Nano),
		})
	}

	return msg, nil
}

func legacyEncodeJSON[T any, P any](items []T, entity string, wrap func(int, []byte) P) ([]P, error) {
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

func legacyAdmitConsumers(consumers []consumerdomain.Consumer, _ string, validate func(int) error) []consumerdomain.Consumer {
	admitted := consumers
	cloned := false
	for i := range consumers {
		err := validate(i)
		if err == nil {
			continue
		}
		if !cloned {
			admitted = slices.Clone(consumers)
			cloned = true
		}
		lb := *admitted[i].LBConfig
		// Keep a malformed smart envelope on the smart strategy path: dropping
		// its ladder must never turn it into a runnable legacy pool.
		lb.Algorithm = algorithm.SmartRouting
		lb.SmartRouting = nil
		admitted[i].LBConfig = &lb
	}
	return admitted
}

func legacyRegistryOwners(registries []registrydomain.Registry) map[ids.RegistryID]ids.GatewayID {
	owners := make(map[ids.RegistryID]ids.GatewayID, len(registries))
	for _, r := range registries {
		owners[r.ID] = r.GatewayID
	}
	return owners
}

func legacyValidateConsumerSmartRouting(c *consumerdomain.Consumer, owners map[ids.RegistryID]ids.GatewayID) error {
	if !legacyHasSmartRouting(c) {
		return nil
	}
	if c.LBConfig.Algorithm != algorithm.SmartRouting {
		return fmt.Errorf("smart_routing requires the smart-routing algorithm")
	}
	// Validate a copy as enabled: inactive consumers and disabled pools are part
	// of the migration preflight, and must pass the same admission fence.
	lb := *c.LBConfig
	lb.Enabled = true
	known := make(map[ids.RegistryID]struct{}, len(c.RegistryIDs))
	for _, id := range c.RegistryIDs {
		if owner, ok := owners[id]; ok && owner == c.GatewayID {
			known[id] = struct{}{}
		}
	}
	if c.Fallback != nil {
		for _, id := range c.Fallback.Chain {
			if owner, ok := owners[id]; ok && owner == c.GatewayID {
				known[id] = struct{}{}
			}
		}
	}
	if err := c.ModelPolicies.Validate(known); err != nil {
		return err
	}
	if err := lb.ValidateTierRegistries(known); err != nil {
		return err
	}
	return lb.Validate(c.ModelPolicies)
}

func legacyHasSmartRouting(c *consumerdomain.Consumer) bool {
	return c.LBConfig != nil && (c.LBConfig.Algorithm == algorithm.SmartRouting || c.LBConfig.SmartRouting != nil)
}

func legacySortData(data *readmodel.Data) {
	sort.SliceStable(data.TenantCaps, func(i, j int) bool { return data.TenantCaps[i].TenantID < data.TenantCaps[j].TenantID })
	sort.SliceStable(data.SessionRevocations, func(i, j int) bool {
		a, b := data.SessionRevocations[i], data.SessionRevocations[j]
		if a.GatewayID != b.GatewayID {
			return a.GatewayID < b.GatewayID
		}
		if a.Org != b.Org {
			return a.Org < b.Org
		}
		return a.Subject < b.Subject
	})
	sort.SliceStable(data.Gateways, func(i, j int) bool { return data.Gateways[i].ID.String() < data.Gateways[j].ID.String() })
	sort.SliceStable(data.Consumers, func(i, j int) bool { return data.Consumers[i].ID.String() < data.Consumers[j].ID.String() })
	sort.SliceStable(data.Registries, func(i, j int) bool { return data.Registries[i].ID.String() < data.Registries[j].ID.String() })
	sort.SliceStable(data.Policies, func(i, j int) bool { return data.Policies[i].ID.String() < data.Policies[j].ID.String() })
	sort.SliceStable(data.Auths, func(i, j int) bool { return data.Auths[i].ID.String() < data.Auths[j].ID.String() })
	sort.SliceStable(data.StoreGrants, func(i, j int) bool {
		a, b := data.StoreGrants[i], data.StoreGrants[j]
		if a.GatewayID != b.GatewayID {
			return a.GatewayID.String() < b.GatewayID.String()
		}
		if a.CatalogCode != b.CatalogCode {
			return a.CatalogCode < b.CatalogCode
		}
		return a.RegistryID.String() < b.RegistryID.String()
	})
	sort.SliceStable(data.StorePolicies, func(i, j int) bool {
		a, b := data.StorePolicies[i], data.StorePolicies[j]
		if a.GatewayID != b.GatewayID {
			return a.GatewayID.String() < b.GatewayID.String()
		}
		if a.PrincipalType != b.PrincipalType {
			return a.PrincipalType < b.PrincipalType
		}
		return a.PrincipalID < b.PrincipalID
	})
	sort.SliceStable(data.StoreEveryone, func(i, j int) bool {
		return data.StoreEveryone[i].GatewayID.String() < data.StoreEveryone[j].GatewayID.String()
	})
	sort.SliceStable(data.KeyGroupBudgets, func(i, j int) bool {
		a, b := data.KeyGroupBudgets[i], data.KeyGroupBudgets[j]
		if a.GatewayID != b.GatewayID {
			return a.GatewayID.String() < b.GatewayID.String()
		}
		return a.GroupID < b.GroupID
	})
	sort.SliceStable(data.Providers, func(i, j int) bool { return data.Providers[i].Code < data.Providers[j].Code })
	sort.SliceStable(data.CatalogModels, func(i, j int) bool {
		if data.CatalogModels[i].ProviderCode != data.CatalogModels[j].ProviderCode {
			return data.CatalogModels[i].ProviderCode < data.CatalogModels[j].ProviderCode
		}
		if data.CatalogModels[i].Model.Slug != data.CatalogModels[j].Model.Slug {
			return data.CatalogModels[i].Model.Slug < data.CatalogModels[j].Model.Slug
		}
		return data.CatalogModels[i].Model.ID.String() < data.CatalogModels[j].Model.ID.String()
	})
	sort.SliceStable(data.PlaygroundTokenKeys, func(i, j int) bool {
		if data.PlaygroundTokenKeys[i].KID != data.PlaygroundTokenKeys[j].KID {
			return data.PlaygroundTokenKeys[i].KID < data.PlaygroundTokenKeys[j].KID
		}
		return data.PlaygroundTokenKeys[i].PEM < data.PlaygroundTokenKeys[j].PEM
	})
}

func legacyStampTenantCaps(data *readmodel.Data, caps map[string]ratelimitdomain.TenantCaps) {
	seen := make(map[string]struct{}, len(data.Gateways))
	for i := range data.Gateways {
		tenantID := data.Gateways[i].TenantID()
		if tenantID == "" {
			continue
		}
		if _, dup := seen[tenantID]; dup {
			continue
		}
		seen[tenantID] = struct{}{}
		if c, ok := caps[tenantID]; ok {
			data.TenantCaps = append(data.TenantCaps, c)
		}
	}
}

func legacyStampSessionRevocations(data *readmodel.Data, rows []readmodel.SessionRevocation) {
	if len(rows) == 0 || len(data.Gateways) == 0 {
		return
	}
	present := make(map[string]struct{}, len(data.Gateways))
	for i := range data.Gateways {
		present[data.Gateways[i].ID.String()] = struct{}{}
	}
	for _, row := range rows {
		if _, ok := present[row.GatewayID]; !ok {
			continue
		}
		data.SessionRevocations = append(data.SessionRevocations, row)
	}
}

func legacyAppendGatewayData(dst *readmodel.Data, gateway gatewaydomain.Gateway, gwData readmodel.Data) {
	dst.Gateways = append(dst.Gateways, gateway)
	dst.Consumers = append(dst.Consumers, gwData.Consumers...)
	dst.Registries = append(dst.Registries, gwData.Registries...)
	dst.Policies = append(dst.Policies, gwData.Policies...)
	dst.Auths = append(dst.Auths, gwData.Auths...)
	dst.StoreGrants = append(dst.StoreGrants, gwData.StoreGrants...)
	dst.StorePolicies = append(dst.StorePolicies, gwData.StorePolicies...)
	dst.StoreEveryone = append(dst.StoreEveryone, gwData.StoreEveryone...)
	dst.KeyGroupBudgets = append(dst.KeyGroupBudgets, gwData.KeyGroupBudgets...)
}

func legacyMergeCatalog(dst *readmodel.Data, catalog readmodel.Data) {
	dst.Providers = append(dst.Providers, catalog.Providers...)
	dst.CatalogModels = append(dst.CatalogModels, catalog.CatalogModels...)
}
