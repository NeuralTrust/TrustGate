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

package topic

import (
	"testing"
	"time"
)

func TestNewRequest(t *testing.T) {
	t.Parallel()

	received := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	cfg := &Config{
		Enabled:   true,
		Topics:    []Topic{{Name: "billing", Definition: "refunds"}},
		Threshold: ptr(0.6),
	}
	req := NewRequest(RequestParams{
		GatewayID:  "gw",
		ConsumerID: "consumer",
		TraceID:    "trace",
		Text:       "where is my refund",
		Config:     cfg,
		ReceivedAt: received,
	})

	if req.GatewayID != "gw" || req.ConsumerID != "consumer" || req.TraceID != "trace" {
		t.Fatalf("identifiers not carried: %+v", req)
	}
	if req.TextHash != HashText("where is my refund") {
		t.Fatalf("TextHash = %q, want the hash of the text", req.TextHash)
	}
	if req.CatalogHash != CatalogHash(cfg.Topics) {
		t.Fatalf("CatalogHash = %q, want the hash of the catalog", req.CatalogHash)
	}
	if req.Threshold == nil || *req.Threshold != 0.6 {
		t.Fatalf("Threshold = %v, want 0.6", req.Threshold)
	}
	if !req.ReceivedAt.Equal(received) {
		t.Fatalf("ReceivedAt = %v, want %v", req.ReceivedAt, received)
	}

	cfg.Topics[0].Name = "changed"
	*cfg.Threshold = 0.1
	if req.Topics[0].Name != "billing" {
		t.Fatal("request shares the catalog with the config")
	}
	if *req.Threshold != 0.6 {
		t.Fatal("request shares the threshold with the config")
	}
}

func TestNewRequestWithoutConfig(t *testing.T) {
	t.Parallel()
	req := NewRequest(RequestParams{Text: "hi"})
	if req.Topics != nil || req.Threshold != nil {
		t.Fatalf("expected no catalog and no threshold, got %+v", req)
	}
	if req.CatalogHash != CatalogHash(nil) {
		t.Fatal("catalog hash of an empty catalog is not stable")
	}
}

func TestCatalogHash(t *testing.T) {
	t.Parallel()

	a := []Topic{{Name: "billing", Definition: "refunds"}, {Name: "legal", Definition: "contracts"}}
	b := []Topic{{Name: "legal", Definition: "contracts"}, {Name: "billing", Definition: "refunds"}}
	if CatalogHash(a) != CatalogHash(b) {
		t.Fatal("hash depends on topic order")
	}

	changedDefinition := []Topic{{Name: "billing", Definition: "invoices"}, {Name: "legal", Definition: "contracts"}}
	if CatalogHash(a) == CatalogHash(changedDefinition) {
		t.Fatal("hash ignores a definition change")
	}

	shifted := []Topic{{Name: "bil", Definition: "lingrefunds"}, {Name: "legal", Definition: "contracts"}}
	if CatalogHash(a) == CatalogHash(shifted) {
		t.Fatal("hash does not separate name from definition")
	}

	if a[0].Name != "billing" {
		t.Fatal("CatalogHash reordered its input")
	}
}
