// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package registry

import (
	"reflect"
	"testing"

	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestSplitCandidates_SortsByNameThenFingerprintAndDedupes(t *testing.T) {
	t.Parallel()
	mk := func(name, fp, def string) domain.ToolCandidate {
		return domain.ToolCandidate{ToolRef: domain.ToolRef{Name: name, Fingerprint: fp}, Definition: []byte(def)}
	}
	in := []domain.ToolCandidate{
		mk("write", "b", `{"n":3}`),
		mk("search", "z", `{"n":2}`),
		mk("search", "a", `{"n":1}`),
		mk("write", "b", `{"n":"dup"}`),
	}
	names, fps, defs := splitCandidates(in)

	if want := []string{"search", "search", "write"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("names = %v, want %v", names, want)
	}
	if want := []string{"a", "z", "b"}; !reflect.DeepEqual(fps, want) {
		t.Fatalf("fingerprints = %v, want %v", fps, want)
	}
	if want := []string{`{"n":1}`, `{"n":2}`, `{"n":3}`}; !reflect.DeepEqual(defs, want) {
		t.Fatalf("definitions = %v, want %v", defs, want)
	}
	if in[0].Name != "write" {
		t.Fatal("splitCandidates must not reorder the caller's slice")
	}
}
