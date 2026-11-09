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

import (
	"slices"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

func TestResolveProviderOptionHeaders_RestoresMaskedValue(t *testing.T) {
	t.Parallel()
	storedValue := "client-secret-value"
	incoming := map[string]any{
		"base_url": "https://llm.internal/v1",
		"headers":  map[string]any{"X-IBM-Client-Id": secret.Mask(storedValue)},
	}
	stored := map[string]any{
		"base_url": "https://llm.internal/v1",
		"headers":  map[string]string{"X-IBM-Client-Id": storedValue},
	}

	marks := ResolveProviderOptionHeaders(incoming, stored, nil)
	headers, ok := ProviderOptionHeaders(incoming)
	if !ok || headers["X-IBM-Client-Id"] != storedValue {
		t.Fatalf("headers = %#v, ok %v", headers, ok)
	}
	if len(marks) != 0 {
		t.Fatalf("marks = %v", marks)
	}
	if got := stored["headers"].(map[string]string)["X-IBM-Client-Id"]; got != storedValue {
		t.Fatalf("stored header mutated: %q", got)
	}
}

func TestResolveProviderOptionHeaders_KeepsUnreadableEmpty(t *testing.T) {
	t.Parallel()
	incoming := map[string]any{
		"headers": map[string]any{"X-IBM-Client-Id": secret.Redacted},
	}
	marks := ResolveProviderOptionHeaders(incoming, nil, []string{"X-IBM-Client-Id"})
	headers, _ := ProviderOptionHeaders(incoming)
	if headers["X-IBM-Client-Id"] != "" || !slices.Equal(marks, []string{"X-IBM-Client-Id"}) {
		t.Fatalf("headers %v marks %v", headers, marks)
	}
}

func TestMaskedProviderOptionHeader_RejectsOrphanMask(t *testing.T) {
	t.Parallel()
	incoming := map[string]any{"headers": map[string]any{"X-IBM-Client-Id": secret.Redacted + "xxxx"}}
	ResolveProviderOptionHeaders(incoming, map[string]any{"headers": map[string]string{}}, nil)
	name, masked := MaskedProviderOptionHeader(incoming)
	if !masked || name != "X-IBM-Client-Id" {
		t.Fatalf("masked header = %q, %v", name, masked)
	}
}
