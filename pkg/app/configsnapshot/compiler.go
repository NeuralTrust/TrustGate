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
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
)

const compilerPageSize = 100

type Compiler struct {
	gateways   GatewayReader
	consumers  ConsumerReader
	registries RegistryReader
	policies   PolicyReader
	auths      AuthReader
	roles      RoleReader
	catalog    CatalogReader
	logger     *slog.Logger
}

func NewCompiler(
	gateways GatewayReader,
	consumers ConsumerReader,
	registries RegistryReader,
	policies PolicyReader,
	auths AuthReader,
	roles RoleReader,
	catalog CatalogReader,
	logger *slog.Logger,
) *Compiler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Compiler{
		gateways:   gateways,
		consumers:  consumers,
		registries: registries,
		policies:   policies,
		auths:      auths,
		roles:      roles,
		catalog:    catalog,
		logger:     logger,
	}
}

func (c *Compiler) Compile(ctx context.Context) (*readmodel.Snapshot, error) {
	gateways, err := c.listGateways(ctx)
	if err != nil {
		return nil, err
	}

	data := readmodel.Data{}
	var skipped int
	for i := range gateways {
		var gwData readmodel.Data
		if err := c.collectGateway(ctx, gateways[i].ID, &gwData); err != nil {
			if errors.Is(err, commonerrors.ErrCorruptData) {
				c.logger.Warn("skipping gateway with corrupt persisted config from snapshot",
					slog.String("component", component),
					slog.String("gateway_id", gateways[i].ID.String()),
					slog.String("error", err.Error()))
				skipped++
				continue
			}
			return nil, err
		}
		data.Gateways = append(data.Gateways, gateways[i])
		data.Consumers = append(data.Consumers, gwData.Consumers...)
		data.Registries = append(data.Registries, gwData.Registries...)
		data.Policies = append(data.Policies, gwData.Policies...)
		data.Auths = append(data.Auths, gwData.Auths...)
		data.Roles = append(data.Roles, gwData.Roles...)
	}

	if skipped > 0 && len(data.Gateways) == 0 {
		return nil, fmt.Errorf("configsnapshot: every gateway (%d) skipped due to corrupt persisted config; refusing to publish empty snapshot: %w", skipped, commonerrors.ErrCorruptData)
	}

	if err := c.collectCatalog(ctx, &data); err != nil {
		return nil, err
	}

	sortData(&data)
	return readmodel.Build(data), nil
}

func (c *Compiler) listGateways(ctx context.Context) ([]gatewaydomain.Gateway, error) {
	out := make([]gatewaydomain.Gateway, 0)
	for page := 1; ; page++ {
		items, _, err := c.gateways.List(ctx, gatewaydomain.ListFilter{Page: page, Size: compilerPageSize})
		if err != nil {
			if errors.Is(err, commonerrors.ErrNotFound) {
				return out, nil
			}
			return nil, fmt.Errorf("configsnapshot: list gateways: %w", err)
		}
		for _, g := range items {
			if g == nil {
				continue
			}
			out = append(out, *g)
		}
		if len(items) < compilerPageSize {
			return out, nil
		}
	}
}

func (c *Compiler) collectGateway(ctx context.Context, gatewayID ids.GatewayID, data *readmodel.Data) error {
	consumers, err := c.consumers.ListByGateway(ctx, gatewayID)
	if err != nil && !errors.Is(err, commonerrors.ErrNotFound) {
		return fmt.Errorf("configsnapshot: list consumers for gateway %s: %w", gatewayID, err)
	}
	for _, cs := range consumers {
		if cs == nil {
			continue
		}
		data.Consumers = append(data.Consumers, *cs)
	}

	registries, err := c.listRegistries(ctx, gatewayID)
	if err != nil {
		return err
	}
	data.Registries = append(data.Registries, registries...)

	policies, err := c.policies.ListByGateway(ctx, gatewayID)
	if err != nil && !errors.Is(err, commonerrors.ErrNotFound) {
		return fmt.Errorf("configsnapshot: list policies for gateway %s: %w", gatewayID, err)
	}
	for _, p := range policies {
		if p == nil {
			continue
		}
		data.Policies = append(data.Policies, *p)
	}

	auths, err := c.listAuths(ctx, gatewayID)
	if err != nil {
		return err
	}
	data.Auths = append(data.Auths, auths...)

	roles, err := c.roles.ListByGateway(ctx, gatewayID)
	if err != nil && !errors.Is(err, commonerrors.ErrNotFound) {
		return fmt.Errorf("configsnapshot: list roles for gateway %s: %w", gatewayID, err)
	}
	for _, r := range roles {
		if r == nil {
			continue
		}
		data.Roles = append(data.Roles, *r)
	}
	return nil
}

func (c *Compiler) listRegistries(ctx context.Context, gatewayID ids.GatewayID) ([]registrydomain.Registry, error) {
	out := make([]registrydomain.Registry, 0)
	for page := 1; ; page++ {
		items, _, err := c.registries.List(ctx, registrydomain.ListFilter{GatewayID: gatewayID, Page: page, Size: compilerPageSize})
		if err != nil {
			if errors.Is(err, commonerrors.ErrNotFound) {
				return out, nil
			}
			return nil, fmt.Errorf("configsnapshot: list registries for gateway %s: %w", gatewayID, err)
		}
		for _, r := range items {
			if r == nil {
				continue
			}
			out = append(out, *r)
		}
		if len(items) < compilerPageSize {
			return out, nil
		}
	}
}

func (c *Compiler) listAuths(ctx context.Context, gatewayID ids.GatewayID) ([]authdomain.Auth, error) {
	out := make([]authdomain.Auth, 0)
	for page := 1; ; page++ {
		items, _, err := c.auths.List(ctx, authdomain.ListFilter{GatewayID: gatewayID, Page: page, Size: compilerPageSize})
		if err != nil {
			if errors.Is(err, commonerrors.ErrNotFound) {
				return out, nil
			}
			return nil, fmt.Errorf("configsnapshot: list auths for gateway %s: %w", gatewayID, err)
		}
		for _, a := range items {
			if a == nil {
				continue
			}
			out = append(out, *a)
		}
		if len(items) < compilerPageSize {
			return out, nil
		}
	}
}

func (c *Compiler) collectCatalog(ctx context.Context, data *readmodel.Data) error {
	providers, err := c.catalog.ListProviders(ctx)
	if err != nil {
		if errors.Is(err, commonerrors.ErrNotFound) {
			return nil
		}
		return fmt.Errorf("configsnapshot: list providers: %w", err)
	}
	data.Providers = append(data.Providers, providers...)
	for i := range providers {
		models, err := c.catalog.ListModelsByProviderCode(ctx, providers[i].Code)
		if err != nil {
			if errors.Is(err, commonerrors.ErrNotFound) {
				continue
			}
			return fmt.Errorf("configsnapshot: list models for provider %s: %w", providers[i].Code, err)
		}
		for j := range models {
			data.CatalogModels = append(data.CatalogModels, readmodel.CatalogModel{
				ProviderCode: providers[i].Code,
				Model:        models[j],
			})
		}
	}
	return nil
}

func sortData(data *readmodel.Data) {
	sort.SliceStable(data.Gateways, func(i, j int) bool { return data.Gateways[i].ID.String() < data.Gateways[j].ID.String() })
	sort.SliceStable(data.Consumers, func(i, j int) bool { return data.Consumers[i].ID.String() < data.Consumers[j].ID.String() })
	sort.SliceStable(data.Registries, func(i, j int) bool { return data.Registries[i].ID.String() < data.Registries[j].ID.String() })
	sort.SliceStable(data.Policies, func(i, j int) bool { return data.Policies[i].ID.String() < data.Policies[j].ID.String() })
	sort.SliceStable(data.Auths, func(i, j int) bool { return data.Auths[i].ID.String() < data.Auths[j].ID.String() })
	sort.SliceStable(data.Roles, func(i, j int) bool { return data.Roles[i].ID.String() < data.Roles[j].ID.String() })
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
}
