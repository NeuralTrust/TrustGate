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

package trafficlabel

import (
	"testing"
	"time"
)

func TestNewRequest(t *testing.T) {
	t.Parallel()

	received := time.Date(2026, 9, 28, 10, 0, 0, 0, time.UTC)
	cfg := enabled()
	sets := []LabelSet{sentiment()}
	req := NewRequest(RequestParams{
		GatewayID:  "gw",
		ConsumerID: "consumer",
		TraceID:    "trace",
		Text:       "where is my refund",
		Config:     cfg,
		LabelSets:  sets,
		ReceivedAt: received,
	})

	if req.GatewayID != "gw" || req.ConsumerID != "consumer" || req.TraceID != "trace" {
		t.Fatalf("identifiers not carried: %+v", req)
	}
	if req.TextHash != HashText("where is my refund") {
		t.Fatalf("TextHash = %q, want the hash of the text", req.TextHash)
	}
	if req.CatalogHash != CatalogHash(sets) {
		t.Fatalf("CatalogHash = %q, want the hash of the label sets", req.CatalogHash)
	}
	if req.RegistryID != testRegistryID || req.Model != "gpt-4o-mini" {
		t.Fatalf("classifier not carried: %+v", req)
	}
	if !req.ReceivedAt.Equal(received) {
		t.Fatalf("ReceivedAt = %v, want %v", req.ReceivedAt, received)
	}

	sets[0].Name = "changed"
	sets[0].Labels[0].Name = "changed"
	if req.LabelSets[0].Name != "Sentiment analysis" || req.LabelSets[0].Labels[0].Name != "positive" {
		t.Fatal("request shares the label sets with the consumer")
	}
}

func TestNewRequestWithoutConfig(t *testing.T) {
	t.Parallel()
	req := NewRequest(RequestParams{Text: "hi"})
	if req.LabelSets != nil || req.RegistryID != "" || req.Model != "" {
		t.Fatalf("expected no label sets and no classifier, got %+v", req)
	}
	if req.CatalogHash != CatalogHash(nil) {
		t.Fatal("catalog hash of an empty list is not stable")
	}
}

func TestCacheKeySeparatesClassifier(t *testing.T) {
	t.Parallel()
	base := CacheKey("gw", "text", "catalog", "registry", "model")
	for name, other := range map[string]string{
		"gateway":  CacheKey("gw2", "text", "catalog", "registry", "model"),
		"text":     CacheKey("gw", "text2", "catalog", "registry", "model"),
		"catalog":  CacheKey("gw", "text", "catalog2", "registry", "model"),
		"registry": CacheKey("gw", "text", "catalog", "registry2", "model"),
		"model":    CacheKey("gw", "text", "catalog", "registry", "model2"),
	} {
		if other == base {
			t.Fatalf("cache key ignores the %s", name)
		}
	}
}
