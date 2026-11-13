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

package secret

import "testing"

func TestMaskPassesReferencesThrough(t *testing.T) {
	t.Parallel()
	ref := "secret://corp-vault/ai-gateway/openai#api_key"
	if got := Mask(ref); got != ref {
		t.Fatalf("Mask(reference) = %q", got)
	}
	if got := Mask("sk-live-1234567890"); got == "sk-live-1234567890" || !IsMasked(got) {
		t.Fatalf("Mask(literal) = %q", got)
	}
	if got := Resolve(ref, "sk-old"); got != ref {
		t.Fatalf("an echoed reference must be kept, got %q", got)
	}
}
