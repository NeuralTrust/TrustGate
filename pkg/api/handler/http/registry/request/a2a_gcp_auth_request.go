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

// A2AGCPAuthRequest takes a service-account key or a service account to
// impersonate; with neither the pod's Application Default Credentials apply.
type A2AGCPAuthRequest struct {
	ServiceAccountJSON        GCPServiceAccountJSON `json:"service_account_json,omitempty" swaggertype:"string"`
	ImpersonateServiceAccount string                `json:"impersonate_service_account,omitempty"`
}
