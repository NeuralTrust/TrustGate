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

package event

// InvalidateRegistryCacheEvent signals that a backend changed and both its
// cached entity and the load balancer instance derived from it must be dropped
// across every process.
type InvalidateRegistryCacheEvent struct {
	GatewayID  string `json:"gateway_id"`
	RegistryID string `json:"registry_id"`
}

func (e InvalidateRegistryCacheEvent) Type() string {
	return InvalidateRegistryCacheEventType
}
