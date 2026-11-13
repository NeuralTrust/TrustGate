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

package localfile

import (
	"os"
	"testing"
)

// The store file shipped next to the compose file must load as is.
func TestShippedExampleParses(t *testing.T) {
	raw, err := os.ReadFile("../../../../downloads/secret-stores.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	stores, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(stores) != 1 || stores[0].Name != "local-files" {
		t.Fatalf("stores = %v, want the one uncommented file store", stores)
	}
}
