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
)

// SharedAccountStateResponse is whether an MCP instance's shared account can be
// used, as a registry listing shows it. It never names the account: that stays
// on the shared-account endpoint, for whoever manages it.
type SharedAccountStateResponse struct {
	Connected      bool `json:"connected"`
	NeedsReconnect bool `json:"needs_reconnect,omitempty"`
}

func FromSharedAccountState(a *appregistry.SharedAccount) *SharedAccountStateResponse {
	if a == nil {
		return nil
	}
	return &SharedAccountStateResponse{Connected: a.Connected, NeedsReconnect: a.NeedsReconnect}
}
