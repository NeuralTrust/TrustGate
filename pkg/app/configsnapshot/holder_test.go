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

package configsnapshot_test

import (
	"testing"

	appsnapshot "github.com/NeuralTrust/TrustGate/pkg/app/configsnapshot"
)

func TestHolderEmpty(t *testing.T) {
	h := appsnapshot.NewHolder()
	if _, _, ok := h.Snapshot(); ok {
		t.Fatalf("expected empty holder to report ok=false")
	}
	if v := h.Version(); v != "" {
		t.Fatalf("expected empty version, got %q", v)
	}
}

func TestHolderSetAndGet(t *testing.T) {
	h := appsnapshot.NewHolder()
	h.Set([]byte("payload"), "v1")

	raw, version, ok := h.Snapshot()
	if !ok {
		t.Fatalf("expected ok=true after set")
	}
	if string(raw) != "payload" || version != "v1" {
		t.Fatalf("unexpected snapshot state: raw=%q version=%q", raw, version)
	}
	if h.Version() != "v1" {
		t.Fatalf("unexpected version: %q", h.Version())
	}

	h.Set([]byte("next"), "v2")
	raw, version, _ = h.Snapshot()
	if string(raw) != "next" || version != "v2" {
		t.Fatalf("expected updated snapshot, got raw=%q version=%q", raw, version)
	}
}
