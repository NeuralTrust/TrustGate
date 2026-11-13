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

import appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"

// SecretStoreUsageResponse is one entity field that references a store.
type SecretStoreUsageResponse struct {
	Entity    string `json:"entity"`
	ID        string `json:"id"`
	Name      string `json:"name"`
	Field     string `json:"field"`
	Reference string `json:"reference"`
	// State is what the gateway's planes last reported: ok, failing, or
	// not_reported when none has resolved the reference since it was set.
	State string `json:"state" enums:"ok,failing,not_reported"`
	// ErrorClass is why a failing reference did not resolve.
	ErrorClass string `json:"error_class,omitempty"`
}

// FromUsages builds the usages response; never nil.
func FromUsages(in []appsecretstore.Usage) []SecretStoreUsageResponse {
	out := make([]SecretStoreUsageResponse, 0, len(in))
	for _, u := range in {
		state := u.State
		if state == "" {
			state = appsecretstore.RefStateNotReported
		}
		out = append(out, SecretStoreUsageResponse{
			Entity: u.Entity, ID: u.ID, Name: u.Name, Field: u.Field, Reference: u.Reference,
			State: state, ErrorClass: u.ErrorClass,
		})
	}
	return out
}
