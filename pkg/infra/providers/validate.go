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

package providers

func ValidateProviderOptions(provider string, options map[string]any) error {
	switch provider {
	case ProviderOpenAICompatible:
		_, err := DecodeOpenAICompatibleOptions(options)
		return err
	case ProviderOpenAI:
		_, err := DecodeOpenAIOptions(options)
		return err
	case ProviderVertex:
		_, err := DecodeVertexOptions(options)
		return err
	default:
		return nil
	}
}
