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

package loadbalancer

import (
	"github.com/NeuralTrust/TrustGate/pkg/domain/embedding"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer/algorithm"
)

const (
	AlgorithmRoundRobin         = algorithm.RoundRobin
	AlgorithmRandom             = algorithm.Random
	AlgorithmWeightedRoundRobin = algorithm.WeightedRoundRobin
	AlgorithmLeastConnections   = algorithm.LeastConnections
	AlgorithmSemantic           = algorithm.Semantic
)

type Strategy interface {
	Next(req *infracontext.RequestContext, exclude map[ids.RegistryID]struct{}) *registry.Registry
	Name() string
}

type StrategyInput struct {
	Algorithm       string
	Registries      []*registry.Registry
	Weights         map[ids.RegistryID]int
	EmbeddingConfig *embedding.Config
}

type Factory interface {
	CreateStrategy(input StrategyInput) (Strategy, error)
}

func Algorithms() []string { return algorithm.Names() }

func IsValidAlgorithm(name string) bool { return algorithm.IsValid(name) }
