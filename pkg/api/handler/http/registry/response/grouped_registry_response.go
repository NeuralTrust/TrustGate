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

package response

import (
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type GroupedRegistryResponse struct {
	View           string                          `json:"view"`
	Groups         []RegistryProviderGroupResponse `json:"groups"`
	TotalGroups    int                             `json:"total_groups"`
	TotalInstances int                             `json:"total_instances"`
}

type RegistryProviderGroupResponse struct {
	Provider      string             `json:"provider"`
	Type          string             `json:"type"`
	InstanceCount int                `json:"instance_count"`
	Instances     []RegistryResponse `json:"instances"`
}

func FromGroupedRegistries(result appregistry.GroupedRegistryResult) GroupedRegistryResponse {
	groups := make([]RegistryProviderGroupResponse, 0, len(result.Groups))
	for _, group := range result.Groups {
		instances := make([]RegistryResponse, 0, len(group.Instances))
		for _, instance := range group.Instances {
			instances = append(instances, FromRegistry(instance))
		}
		groups = append(groups, RegistryProviderGroupResponse{
			Provider:      group.Provider,
			Type:          string(domain.TypeLLM),
			InstanceCount: len(instances),
			Instances:     instances,
		})
	}
	return GroupedRegistryResponse{
		View:           "grouped",
		Groups:         groups,
		TotalGroups:    len(groups),
		TotalInstances: result.TotalInstances,
	}
}
