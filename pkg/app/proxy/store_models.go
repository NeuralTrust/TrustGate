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
	"iter"
	"slices"
	"strings"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
)

type StoreModelsInput struct {
	Links []appconsumer.StoreLink
	Data  *appconsumer.Data
}

//go:generate mockery --name=StoreModels --dir=. --output=./mocks --filename=store_models_mock.go --case=underscore --with-expecter
type StoreModels interface {
	List(ctx context.Context, in StoreModelsInput) (*ModelsList, error)
	Get(ctx context.Context, in StoreModelsInput, id string) (*ModelCard, error)
}

var _ StoreModels = (*storeModels)(nil)

type storeModels struct {
	lister *modelsLister
}

func NewStoreModels(resolver approuting.Resolver, catalog appcatalog.Service) StoreModels {
	return &storeModels{lister: &modelsLister{resolver: resolver, catalog: catalog}}
}

func (s *storeModels) List(ctx context.Context, in StoreModelsInput) (*ModelsList, error) {
	cards := make([]ModelCard, 0)
	seen := make(map[string]struct{})
	for card, err := range s.cards(ctx, in) {
		if err != nil {
			return nil, err
		}
		if _, dup := seen[card.ID]; !dup {
			seen[card.ID] = struct{}{}
			cards = append(cards, card)
		}
	}
	slices.SortFunc(cards, func(a, b ModelCard) int { return strings.Compare(a.ID, b.ID) })
	return &ModelsList{Object: "list", Data: cards}, nil
}

func (s *storeModels) Get(ctx context.Context, in StoreModelsInput, id string) (*ModelCard, error) {
	for card, err := range s.cards(ctx, in) {
		if err != nil {
			return nil, err
		}
		if card.ID == id {
			return &card, nil
		}
	}
	return nil, ErrModelNotFound
}

func (s *storeModels) cards(ctx context.Context, in StoreModelsInput) iter.Seq2[ModelCard, error] {
	return func(yield func(ModelCard, error) bool) {
		listed := make(map[string][]catalogdomain.Model)
		for _, link := range storeScope(in.Links) {
			cards, err := s.lister.collect(ctx, ListModelsInput{Consumer: link.Consumer, Data: in.Data, Keep: link.primaryFilter()}, listed)
			if err != nil {
				yield(ModelCard{}, err)
				return
			}
			for _, card := range cards {
				if !yield(card, nil) {
					return
				}
			}
		}
	}
}
