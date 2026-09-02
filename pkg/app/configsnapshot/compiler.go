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
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/listing"
	policydomain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	roledomain "github.com/NeuralTrust/TrustGate/pkg/domain/role"
	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
	"golang.org/x/sync/errgroup"
)

const compilerPageSize = 100

// compilerBulkPageSize is the page size for the bulk collect path's
// whole-table scans, where fewer round-trips matter more than page weight.
const compilerBulkPageSize = 500

// compilerConcurrency bounds how many gateways are collected from the database
// at once on the per-gateway fallback path. Each gateway costs several
// sequential queries; collecting gateways serially makes compile time grow
// linearly with the tenant count, which directly delays config propagation to
// the data planes.
const compilerConcurrency = 8

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
	return c.CompileFor(ctx, "")
}

func (c *Compiler) CompileFor(ctx context.Context, scope string) (*readmodel.Snapshot, error) {
	gateways, err := c.listGateways(ctx)
	if err != nil {
		return nil, err
	}
	if scope != "" {
		scoped := make([]gatewaydomain.Gateway, 0, 1)
		for i := range gateways {
			if gateways[i].ID.String() == scope {
				scoped = append(scoped, gateways[i])
			}
		}
		gateways = scoped
	} else {
		// The global snapshot feeds hosted data planes; gateways bound to a
		// customer-run (hybrid) data plane only travel in their own scoped
		// snapshot, so a hosted plane cannot even resolve them.
		gateways = withoutHybridGateways(gateways)
	}

	collected, err := c.collectGateways(ctx, gateways)
	if err != nil {
		return nil, err
	}

	data := readmodel.Data{}
	var skipped int
	for i := range gateways {
		if collected[i] == nil {
			skipped++
			continue
		}
		appendGatewayData(&data, gateways[i], *collected[i])
	}

	if skipped > 0 && skipped == len(gateways) {
		return nil, fmt.Errorf("configsnapshot: every gateway (%d) skipped due to corrupt persisted config; refusing to publish empty snapshot: %w", skipped, commonerrors.ErrCorruptData)
	}

	cat, err := c.collectCatalogData(ctx)
	if err != nil {
		return nil, err
	}
	mergeCatalog(&data, cat)

	sortData(&data)
	return readmodel.Build(data), nil
}

// CompileAll compiles the global snapshot, one tenant-only snapshot per
// gateway scope, and the shared catalog as its own snapshot. The catalog
// (providers + models, usually the bulk of the encoded bytes) is deliberately
// NOT merged into the global or scoped snapshots: the dispatcher encodes it
// once and appends the encoded bytes to every snapshot it publishes, instead
// of re-encoding the same catalog per gateway on every compile.
func (c *Compiler) CompileAll(ctx context.Context) (*readmodel.Snapshot, map[string]*readmodel.Snapshot, *readmodel.Snapshot, error) {
	gateways, err := c.listGateways(ctx)
	if err != nil {
		return nil, nil, nil, err
	}

	collected, err := c.collectGateways(ctx, gateways)
	if err != nil {
		return nil, nil, nil, err
	}

	global := readmodel.Data{}
	buckets := map[string]*readmodel.Data{}
	var skipped int
	for i := range gateways {
		if collected[i] == nil {
			skipped++
			continue
		}
		// Hybrid gateways stay out of the global snapshot (hosted data planes
		// must not serve them) but keep their scoped snapshot, which is what
		// their own data plane subscribes to.
		if !gateways[i].ServedByHybridDataPlane() {
			appendGatewayData(&global, gateways[i], *collected[i])
		}
		if scope := gateways[i].ID.String(); scope != "" {
			bucket, ok := buckets[scope]
			if !ok {
				bucket = &readmodel.Data{}
				buckets[scope] = bucket
			}
			appendGatewayData(bucket, gateways[i], *collected[i])
		}
	}

	if skipped > 0 && skipped == len(gateways) {
		return nil, nil, nil, fmt.Errorf("configsnapshot: every gateway (%d) skipped due to corrupt persisted config; refusing to publish empty snapshot: %w", skipped, commonerrors.ErrCorruptData)
	}

	cat, err := c.collectCatalogData(ctx)
	if err != nil {
		return nil, nil, nil, err
	}
	catData := readmodel.Data{}
	mergeCatalog(&catData, cat)
	sortData(&catData)

	sortData(&global)

	scoped := make(map[string]*readmodel.Snapshot, len(buckets))
	for scope, bucket := range buckets {
		sortData(bucket)
		scoped[scope] = readmodel.Build(*bucket)
	}
	return readmodel.Build(global), scoped, readmodel.Build(catData), nil
}

// withoutHybridGateways drops gateways whose entitlements bind them to a
// customer-run data plane.
func withoutHybridGateways(gateways []gatewaydomain.Gateway) []gatewaydomain.Gateway {
	hosted := make([]gatewaydomain.Gateway, 0, len(gateways))
	for i := range gateways {
		if gateways[i].ServedByHybridDataPlane() {
			continue
		}
		hosted = append(hosted, gateways[i])
	}
	return hosted
}

func appendGatewayData(dst *readmodel.Data, gateway gatewaydomain.Gateway, gwData readmodel.Data) {
	dst.Gateways = append(dst.Gateways, gateway)
	dst.Consumers = append(dst.Consumers, gwData.Consumers...)
	dst.Registries = append(dst.Registries, gwData.Registries...)
	dst.Policies = append(dst.Policies, gwData.Policies...)
	dst.Auths = append(dst.Auths, gwData.Auths...)
	dst.Roles = append(dst.Roles, gwData.Roles...)
}

func mergeCatalog(dst *readmodel.Data, catalog readmodel.Data) {
	dst.Providers = append(dst.Providers, catalog.Providers...)
	dst.CatalogModels = append(dst.CatalogModels, catalog.CatalogModels...)
}

func (c *Compiler) collectCatalogData(ctx context.Context) (readmodel.Data, error) {
	var data readmodel.Data
	if err := c.collectCatalog(ctx, &data); err != nil {
		return readmodel.Data{}, err
	}
	return data, nil
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

// collectGateways loads every gateway's config and returns per-gateway data
// aligned by index with gateways. It prefers the bulk path -- one paged scan
// per entity table, so compile latency stays flat as the tenant count grows --
// and falls back to per-gateway collection when a bulk scan hits corrupt
// persisted config, so a corrupt tenant still only knocks out its own gateway.
// A nil entry marks a gateway skipped for corrupt persisted config.
func (c *Compiler) collectGateways(ctx context.Context, gateways []gatewaydomain.Gateway) ([]*readmodel.Data, error) {
	byGateway, err := c.collectAllBulk(ctx)
	if err == nil {
		out := make([]*readmodel.Data, len(gateways))
		for i := range gateways {
			if d, ok := byGateway[gateways[i].ID]; ok {
				out[i] = d
			} else {
				out[i] = &readmodel.Data{}
			}
		}
		return out, nil
	}
	if !errors.Is(err, commonerrors.ErrCorruptData) {
		return nil, err
	}
	c.logger.Warn("bulk snapshot collect hit corrupt persisted config; falling back to per-gateway collect",
		slog.String("component", component),
		slog.String("error", err.Error()))
	return c.collectGatewaysEach(ctx, gateways)
}

// collectAllBulk loads the five gateway-scoped entity tables with one paged
// scan each and groups the rows by gateway in memory. All snapshot data is
// sorted before encoding, so grouping order never affects version hashes.
func (c *Compiler) collectAllBulk(ctx context.Context) (map[ids.GatewayID]*readmodel.Data, error) {
	var (
		consumers  []*consumerdomain.Consumer
		registries []*registrydomain.Registry
		policies   []*policydomain.Policy
		auths      []*authdomain.Auth
		roles      []*roledomain.Role
	)
	g, gctx := errgroup.WithContext(ctx)
	g.Go(func() (err error) {
		consumers, err = listAll(gctx, "consumers", func(ctx context.Context, page int) ([]*consumerdomain.Consumer, int, error) {
			return c.consumers.List(ctx, consumerdomain.ListFilter{Page: listing.Page{Number: page, Size: compilerBulkPageSize}})
		})
		return err
	})
	g.Go(func() (err error) {
		registries, err = listAll(gctx, "registries", func(ctx context.Context, page int) ([]*registrydomain.Registry, int, error) {
			return c.registries.List(ctx, registrydomain.ListFilter{Page: page, Size: compilerBulkPageSize})
		})
		return err
	})
	g.Go(func() (err error) {
		policies, err = listAll(gctx, "policies", func(ctx context.Context, page int) ([]*policydomain.Policy, int, error) {
			return c.policies.List(ctx, policydomain.ListFilter{Page: listing.Page{Number: page, Size: compilerBulkPageSize}})
		})
		return err
	})
	g.Go(func() (err error) {
		auths, err = listAll(gctx, "auths", func(ctx context.Context, page int) ([]*authdomain.Auth, int, error) {
			return c.auths.List(ctx, authdomain.ListFilter{Page: listing.Page{Number: page, Size: compilerBulkPageSize}})
		})
		return err
	})
	g.Go(func() (err error) {
		roles, err = listAll(gctx, "roles", func(ctx context.Context, page int) ([]*roledomain.Role, int, error) {
			return c.roles.List(ctx, roledomain.ListFilter{Page: listing.Page{Number: page, Size: compilerBulkPageSize}})
		})
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}

	byGateway := make(map[ids.GatewayID]*readmodel.Data)
	bucket := func(id ids.GatewayID) *readmodel.Data {
		d, ok := byGateway[id]
		if !ok {
			d = &readmodel.Data{}
			byGateway[id] = d
		}
		return d
	}
	for _, x := range consumers {
		if x != nil {
			b := bucket(x.GatewayID)
			b.Consumers = append(b.Consumers, *x)
		}
	}
	for _, x := range registries {
		if x != nil {
			b := bucket(x.GatewayID)
			b.Registries = append(b.Registries, *x)
		}
	}
	for _, x := range policies {
		if x != nil {
			b := bucket(x.GatewayID)
			b.Policies = append(b.Policies, *x)
		}
	}
	for _, x := range auths {
		if x != nil {
			b := bucket(x.GatewayID)
			b.Auths = append(b.Auths, *x)
		}
	}
	for _, x := range roles {
		if x != nil {
			b := bucket(x.GatewayID)
			b.Roles = append(b.Roles, *x)
		}
	}
	return byGateway, nil
}

// listAll pages one entity table to exhaustion via fetch(page).
func listAll[T any](ctx context.Context, entity string, fetch func(ctx context.Context, page int) ([]T, int, error)) ([]T, error) {
	out := make([]T, 0)
	for page := 1; ; page++ {
		items, _, err := fetch(ctx, page)
		if err != nil {
			if errors.Is(err, commonerrors.ErrNotFound) {
				return out, nil
			}
			return nil, fmt.Errorf("configsnapshot: list %s: %w", entity, err)
		}
		out = append(out, items...)
		if len(items) < compilerBulkPageSize {
			return out, nil
		}
	}
}

// collectGatewaysEach loads each gateway's config concurrently, bounded by
// compilerConcurrency. A nil entry marks a gateway skipped for corrupt
// persisted config; any other collect error fails the whole compile. Callers
// append the results in slice order, so the compiled snapshot stays
// byte-identical to a serial collect and version hashes remain stable.
func (c *Compiler) collectGatewaysEach(ctx context.Context, gateways []gatewaydomain.Gateway) ([]*readmodel.Data, error) {
	results := make([]*readmodel.Data, len(gateways))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(compilerConcurrency)
	for i := range gateways {
		g.Go(func() error {
			var gwData readmodel.Data
			if err := c.collectGateway(gctx, gateways[i].ID, &gwData); err != nil {
				if errors.Is(err, commonerrors.ErrCorruptData) {
					c.logger.Warn("skipping gateway with corrupt persisted config from snapshot",
						slog.String("component", component),
						slog.String("gateway_id", gateways[i].ID.String()),
						slog.String("error", err.Error()))
					return nil
				}
				return err
			}
			results[i] = &gwData
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return results, nil
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
		items, _, err := c.auths.List(ctx, authdomain.ListFilter{GatewayID: gatewayID, Page: listing.Page{Number: page, Size: compilerPageSize}})
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

	// One models query per provider; run them concurrently and append in
	// provider order so the snapshot bytes stay deterministic.
	modelsByProvider := make([][]catalogdomain.Model, len(providers))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(compilerConcurrency)
	for i := range providers {
		g.Go(func() error {
			models, err := c.catalog.ListModelsByProviderCode(gctx, providers[i].Code)
			if err != nil {
				if errors.Is(err, commonerrors.ErrNotFound) {
					return nil
				}
				return fmt.Errorf("configsnapshot: list models for provider %s: %w", providers[i].Code, err)
			}
			modelsByProvider[i] = models
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}
	for i := range providers {
		for j := range modelsByProvider[i] {
			data.CatalogModels = append(data.CatalogModels, readmodel.CatalogModel{
				ProviderCode: providers[i].Code,
				Model:        modelsByProvider[i][j],
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
