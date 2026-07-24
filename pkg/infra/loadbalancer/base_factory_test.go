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

package loadbalancer_test

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/loadbalancer"
)

func TestBaseFactory_CreateStrategy_KnownAlgorithms(t *testing.T) {
	t.Parallel()
	factory := loadbalancer.NewBaseFactory(nil, nil, nil, nil)
	registries := []*registry.Registry{{ID: ids.New[ids.RegistryKind](), Name: "a", LLMTarget: &registry.LLMTarget{Provider: "openai"}}}

	cases := []struct {
		name     string
		alg      string
		wantName string
	}{
		{name: "round-robin", alg: loadbalancer.AlgorithmRoundRobin, wantName: "round-robin"},
		{name: "random", alg: loadbalancer.AlgorithmRandom, wantName: "random"},
		{name: "weighted", alg: loadbalancer.AlgorithmWeightedRoundRobin, wantName: "weighted-round-robin"},
		{name: "least-conn", alg: loadbalancer.AlgorithmLeastConnections, wantName: "least-connections"},
		{name: "semantic", alg: loadbalancer.AlgorithmSemantic, wantName: "semantic"},
		{name: "smart-routing", alg: loadbalancer.AlgorithmSmartRouting, wantName: "smart-routing"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := factory.CreateStrategy(loadbalancer.StrategyInput{
				Algorithm:  tc.alg,
				Registries: registries,
			})
			if err != nil {
				t.Fatalf("CreateStrategy(%s) returned error: %v", tc.alg, err)
			}
			if s.Name() != tc.wantName {
				t.Fatalf("Name() = %q, want %q", s.Name(), tc.wantName)
			}
		})
	}
}

func TestBaseFactory_CreateStrategy_UnknownAlgorithm(t *testing.T) {
	t.Parallel()
	factory := loadbalancer.NewBaseFactory(nil, nil, nil, nil)
	_, err := factory.CreateStrategy(loadbalancer.StrategyInput{Algorithm: "bogus"})
	if err == nil {
		t.Fatal("expected error for unknown algorithm")
	}
	if errors.Is(err, nil) {
		t.Fatalf("err = %v", err)
	}
}

func TestExportedConstantsMatchAlgorithmPackage(t *testing.T) {
	t.Parallel()
	algs := loadbalancer.Algorithms()
	if len(algs) != 6 {
		t.Fatalf("len(Algorithms) = %d, want 6", len(algs))
	}
	for _, a := range algs {
		if !loadbalancer.IsValidAlgorithm(a) {
			t.Fatalf("IsValidAlgorithm(%q) returned false but value is in Algorithms()", a)
		}
	}
}
