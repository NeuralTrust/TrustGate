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
	"slices"
	"strings"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
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
	lister ModelsLister
}

func NewStoreModels(lister ModelsLister) StoreModels {
	return &storeModels{lister: lister}
}

func (s *storeModels) List(ctx context.Context, in StoreModelsInput) (*ModelsList, error) {
	cards := make([]ModelCard, 0)
	seen := make(map[string]struct{})
	for _, link := range storeScope(in.Links) {
		list, err := s.lister.List(ctx, ListModelsInput{Consumer: link.Consumer, Data: in.Data, Keep: link.primaryFilter()})
		if err != nil {
			return nil, err
		}
		for _, card := range list.Data {
			if _, dup := seen[card.ID]; !dup {
				seen[card.ID] = struct{}{}
				cards = append(cards, card)
			}
		}
	}
	slices.SortFunc(cards, func(a, b ModelCard) int { return strings.Compare(a.ID, b.ID) })
	return &ModelsList{Object: "list", Data: cards}, nil
}

func (s *storeModels) Get(ctx context.Context, in StoreModelsInput, id string) (*ModelCard, error) {
	list, err := s.List(ctx, in)
	if err != nil {
		return nil, err
	}
	for i := range list.Data {
		if list.Data[i].ID == id {
			return &list.Data[i], nil
		}
	}
	return nil, ErrModelNotFound
}
