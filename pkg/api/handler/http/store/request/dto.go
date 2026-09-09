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

package request

type SetGrant struct {
	CatalogCode string   `json:"catalog_code"`
	RegistryID  string   `json:"registry_id"`
	Groups      []string `json:"groups"`
	Users       []string `json:"users"`
}

type SetPolicy struct {
	PrincipalType string `json:"principal_type"`
	PrincipalID   string `json:"principal_id"`
	Mode          string `json:"mode"`
}

type Install struct {
	PrincipalSub string   `json:"principal_sub"`
	Code         string   `json:"code"`
	Groups       []string `json:"groups"`
	InstanceID   string   `json:"instance_id"`
	// Reason is why the user wants the server, in their own words. Kept only on
	// a request an approver has to decide, and shown to them there.
	Reason string `json:"reason"`
}

type Decide struct {
	PrincipalSub string `json:"principal_sub"`
	Code         string `json:"code"`
	InstanceID   string `json:"instance_id"`
	GrantToGroup string `json:"grant_to_group"`
}
