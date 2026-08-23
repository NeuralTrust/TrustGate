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

package proxy

import (
	"context"
	"errors"
	"sort"
	"strings"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
)

var ErrModelNotFound = errors.New("model not found")

type ListModelsInput struct {
	Consumer *appconsumer.RoutableConsumer
	Data     *appconsumer.Data
	RoleIDs  []ids.RoleID
}

type ModelCard struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	OwnedBy string `json:"owned_by"`
}

type ModelsList struct {
	Object string      `json:"object"`
	Data   []ModelCard `json:"data"`
}

type ModelsLister interface {
	List(ctx context.Context, in ListModelsInput) (*ModelsList, error)
	Get(ctx context.Context, in ListModelsInput, id string) (*ModelCard, error)
}

type modelsLister struct {
	resolver approuting.Resolver
	catalog  appcatalog.Service
}

func NewModelsLister(resolver approuting.Resolver, catalog appcatalog.Service) ModelsLister {
	return &modelsLister{resolver: resolver, catalog: catalog}
}

func (l *modelsLister) List(ctx context.Context, in ListModelsInput) (*ModelsList, error) {
	cards, err := l.collect(ctx, in)
	if err != nil {
		return nil, err
	}
	if cards == nil {
		cards = []ModelCard{}
	}
	return &ModelsList{Object: "list", Data: cards}, nil
}

func (l *modelsLister) Get(ctx context.Context, in ListModelsInput, id string) (*ModelCard, error) {
	cards, err := l.collect(ctx, in)
	if err != nil {
		return nil, err
	}
	for i := range cards {
		if cards[i].ID == id {
			return &cards[i], nil
		}
	}
	return nil, ErrModelNotFound
}

func (l *modelsLister) collect(ctx context.Context, in ListModelsInput) ([]ModelCard, error) {
	if l == nil || l.resolver == nil || in.Consumer == nil || in.Consumer.Consumer == nil {
		return nil, nil
	}
	candidates, err := l.resolver.Resolve(approuting.ResolveInput{
		Consumer:   in.Consumer,
		Roles:      effectiveRoles(in.Data, in.RoleIDs),
		Registries: registryLookup(in.Data),
	})
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{})
	cards := make([]ModelCard, 0)
	for _, candidate := range candidates.Candidates() {
		if candidate.Registry == nil {
			continue
		}
		provider := candidate.Registry.Provider()
		modelIDs, err := l.candidateModels(ctx, in.Consumer, candidate)
		if err != nil {
			return nil, err
		}
		for _, id := range modelIDs {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			cards = append(cards, ModelCard{ID: id, Object: "model", OwnedBy: provider})
		}
	}
	sort.Slice(cards, func(i, j int) bool { return cards[i].ID < cards[j].ID })
	return cards, nil
}

func (l *modelsLister) candidateModels(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	candidate routingdomain.Candidate,
) ([]string, error) {
	if candidate.Registry == nil {
		return nil, nil
	}
	provider := candidate.Registry.Provider()
	if provider == "" {
		return nil, nil
	}
	modelIDs, catalogBySlug, err := l.candidateModelSources(ctx, rc, candidate, provider)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(modelIDs))
	for _, id := range modelIDs {
		if !isNativeModelID(id) {
			continue
		}
		if !modelServable(provider, id, catalogBySlug[id]) {
			continue
		}
		out = append(out, id)
	}
	return out, nil
}

func (l *modelsLister) candidateModelSources(
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	candidate routingdomain.Candidate,
	provider string,
) ([]string, map[string]catalogdomain.Model, error) {
	catalogBySlug := map[string]catalogdomain.Model{}
	if candidate.Allowed != nil {
		return unionModelIDs(candidate.Allowed, poolMemberModels(rc, candidate.Registry.ID)), catalogBySlug, nil
	}
	if l.catalog == nil {
		return nil, catalogBySlug, nil
	}
	models, err := l.catalog.ListModels(ctx, provider)
	if err != nil {
		return nil, nil, err
	}
	modelIDs := make([]string, 0, len(models))
	for _, model := range models {
		modelIDs = append(modelIDs, model.Slug)
		catalogBySlug[model.Slug] = model
	}
	return modelIDs, catalogBySlug, nil
}

func poolMemberModels(rc *appconsumer.RoutableConsumer, registryID ids.RegistryID) []string {
	if rc == nil || rc.Consumer == nil || rc.Consumer.LBConfig == nil {
		return nil
	}
	var out []string
	for _, member := range rc.Consumer.LBConfig.Members {
		if member.RegistryID == registryID && len(member.Models) > 0 {
			out = append(out, member.Models...)
		}
	}
	return out
}

func unionModelIDs(lists ...[]string) []string {
	seen := make(map[string]struct{})
	out := make([]string, 0)
	for _, list := range lists {
		for _, id := range list {
			if _, dup := seen[id]; dup {
				continue
			}
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

func isNativeModelID(id string) bool {
	id = strings.TrimSpace(id)
	if id == "" || strings.EqualFold(id, "auto") {
		return false
	}
	if strings.HasPrefix(id, "@") {
		return false
	}
	return !strings.HasPrefix(strings.ToLower(id), "pool:")
}

func modelServable(provider, slug string, model catalogdomain.Model) bool {
	for _, capability := range inferModelCapabilities(slug, model.Capabilities) {
		if providers.SupportsCapability(provider, capability) {
			return true
		}
	}
	return false
}

func inferModelCapabilities(slug string, caps map[string]any) []string {
	var out []string
	if capabilityFlag(caps, "chat", "text") {
		out = append(out, providers.CapabilityChat)
	}
	if capabilityFlag(caps, providers.CapabilityEmbeddings, "embedding", "embed") {
		out = append(out, providers.CapabilityEmbeddings)
	}
	if capabilityFlag(caps, providers.CapabilityRerank, "reranking") {
		out = append(out, providers.CapabilityRerank)
	}
	if len(out) > 0 {
		return out
	}
	lower := strings.ToLower(slug)
	switch {
	case strings.Contains(lower, "embed"):
		return []string{providers.CapabilityEmbeddings}
	case strings.Contains(lower, "rerank"):
		return []string{providers.CapabilityRerank}
	default:
		return []string{providers.CapabilityChat}
	}
}

func capabilityFlag(caps map[string]any, keys ...string) bool {
	if caps == nil {
		return false
	}
	for _, key := range keys {
		value, ok := caps[key]
		if !ok {
			continue
		}
		switch typed := value.(type) {
		case bool:
			if typed {
				return true
			}
		case string:
			if typed != "" && !strings.EqualFold(typed, "false") && typed != "0" {
				return true
			}
		}
	}
	return false
}
