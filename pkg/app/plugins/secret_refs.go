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

package plugins

import (
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

// withoutSecretReferences returns settings with every reference-shaped value
// at plugin's declared credential paths emptied. A reference that reached a
// plan unresolved must never be sent as the credential: the plugin then
// fails as it does with a missing credential, under its policy's mode.
func withoutSecretReferences(plugin Plugin, settings map[string]any) map[string]any {
	c, ok := plugin.(CredentialSettings)
	if !ok {
		return settings
	}
	var blank map[string]string
	for _, path := range c.CredentialPaths() {
		if v, ok := secret.SettingString(settings, path); ok && secretref.IsRef(v) {
			if blank == nil {
				blank = map[string]string{}
			}
			blank[path] = ""
		}
	}
	if blank == nil {
		return settings
	}
	return secret.WithSettingStrings(settings, blank)
}
