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

package registry

import (
	"context"
	"fmt"
	"sort"
	"strings"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

const (
	groupedRegistryBatchSize = 100
	MaxGroupedRegistryCount  = 200
)

type RegistryProviderGroup struct {
	Provider  string
	Instances []*domain.Registry
}

type GroupedRegistryResult struct {
	Groups         []RegistryProviderGroup
	TotalInstances int
}

//go:generate mockery --name=GroupedFinder --dir=. --output=./mocks --filename=registry_grouped_finder_mock.go --case=underscore --with-expecter
type GroupedFinder interface {
	Find(ctx context.Context, gatewayID ids.GatewayID) (GroupedRegistryResult, error)
}

var _ GroupedFinder = (*groupedFinder)(nil)

type groupedFinder struct {
	repo domain.Repository
}

type sortableRegistry struct {
	registry *domain.Registry
	nameKey  string
	idKey    string
}

func NewGroupedFinder(repo domain.Repository) GroupedFinder {
	return &groupedFinder{repo: repo}
}

func (f *groupedFinder) Find(ctx context.Context, gatewayID ids.GatewayID) (GroupedRegistryResult, error) {
	byProvider := make(map[string][]sortableRegistry)
	fetched := 0
	total := 0

	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return GroupedRegistryResult{}, err
		}
		items, pageTotal, err := f.repo.List(ctx, domain.ListFilter{
			GatewayID: gatewayID,
			Page:      page,
			Size:      groupedRegistryBatchSize,
		})
		if err != nil {
			return GroupedRegistryResult{}, fmt.Errorf("list registries: %w", err)
		}
		if err := ctx.Err(); err != nil {
			return GroupedRegistryResult{}, err
		}
		if pageTotal > MaxGroupedRegistryCount {
			return GroupedRegistryResult{}, fmt.Errorf(
				"grouped registry view supports at most %d registries; gateway has %d: %w",
				MaxGroupedRegistryCount,
				pageTotal,
				commonerrors.ErrResultTooLarge,
			)
		}
		total = pageTotal
		fetched += len(items)
		if fetched > MaxGroupedRegistryCount {
			return GroupedRegistryResult{}, fmt.Errorf(
				"grouped registry view fetched more than %d registries: %w",
				MaxGroupedRegistryCount,
				commonerrors.ErrResultTooLarge,
			)
		}
		for _, item := range items {
			if item == nil || (item.Type != "" && item.Type != domain.TypeLLM) {
				continue
			}
			provider := item.Provider()
			if provider == "" {
				continue
			}
			byProvider[provider] = append(byProvider[provider], sortableRegistry{
				registry: item,
				nameKey:  strings.ToLower(item.Name),
				idKey:    item.ID.String(),
			})
		}
		if fetched >= total || len(items) == 0 {
			break
		}
	}
	if err := ctx.Err(); err != nil {
		return GroupedRegistryResult{}, err
	}

	groups := make([]RegistryProviderGroup, 0, len(byProvider))
	totalInstances := 0
	for provider, sortableInstances := range byProvider {
		if err := ctx.Err(); err != nil {
			return GroupedRegistryResult{}, err
		}
		sort.Slice(sortableInstances, func(i, j int) bool {
			if sortableInstances[i].nameKey != sortableInstances[j].nameKey {
				return sortableInstances[i].nameKey < sortableInstances[j].nameKey
			}
			return sortableInstances[i].idKey < sortableInstances[j].idKey
		})
		instances := make([]*domain.Registry, 0, len(sortableInstances))
		for _, instance := range sortableInstances {
			instances = append(instances, instance.registry)
		}
		groups = append(groups, RegistryProviderGroup{
			Provider:  provider,
			Instances: instances,
		})
		totalInstances += len(instances)
	}
	sort.Slice(groups, func(i, j int) bool {
		return groups[i].Provider < groups[j].Provider
	})

	return GroupedRegistryResult{
		Groups:         groups,
		TotalInstances: totalInstances,
	}, nil
}
