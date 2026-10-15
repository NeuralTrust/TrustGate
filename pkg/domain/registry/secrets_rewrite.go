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

package registry

// SecretsRewriteReport summarises one pass that re-saves stored MCP targets
// with their credentials encrypted.
type SecretsRewriteReport struct {
	// Scanned counts the MCP targets visited.
	Scanned int
	// Encrypted counts targets re-saved because a credential was stored
	// unencrypted.
	Encrypted int
	// Fixed counts targets the pass's fix function changed.
	Fixed int
	// Failed counts targets left as they were because they could not be read
	// or written; a later pass retries them.
	Failed int
}
