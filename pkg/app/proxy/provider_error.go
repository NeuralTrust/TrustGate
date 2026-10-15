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

import "github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"

func responseCarriesProviderError(resp *ProviderResponse) bool {
	body := providerWording(resp)
	if len(body) == 0 {
		return false
	}
	return adapter.BodyCarriesRetryableError(body)
}

func responseCarriesModelNotFound(resp *ProviderResponse) bool {
	body := providerWording(resp)
	if len(body) == 0 {
		return false
	}
	return adapter.BodyCarriesModelNotFound(body)
}

// providerWording is the body the provider sent, before it was rewritten for
// the client, so the checks match the provider's own error types.
func providerWording(resp *ProviderResponse) []byte {
	if resp == nil {
		return nil
	}
	if resp.upstreamBody != nil {
		return resp.upstreamBody
	}
	return resp.Body
}
