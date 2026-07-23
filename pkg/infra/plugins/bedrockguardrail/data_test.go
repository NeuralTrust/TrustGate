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

package bedrockguardrail

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
)

func TestSetExtrasNilSafe(t *testing.T) {
	t.Parallel()
	setExtras(nil, &Data{Decision: "allowed"})
	setExtras(nil, nil)
}

func TestRecordScore(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		data      *Data
		wantSet   bool
		wantLabel string
	}{
		{name: "prefers name", data: &Data{Name: "HATE", Policy: "content"}, wantSet: true, wantLabel: "HATE"},
		{name: "falls back to policy", data: &Data{Policy: "sensitive_information"}, wantSet: true, wantLabel: "sensitive_information"},
		{name: "no label", data: &Data{}, wantSet: false},
		{name: "nil data", data: nil, wantSet: false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			rt := trace.New("t", trace.Metadata{})
			span := rt.StartSpan(trace.SpanPlugin, PluginName)
			recordScore(metrics.NewEventContext(span), tc.data)

			attrs := span.PluginAttrsCopy()
			if !tc.wantSet {
				if attrs.ScoreLabel != "" || attrs.Score != nil {
					t.Fatalf("expected no score, got label=%q score=%v", attrs.ScoreLabel, attrs.Score)
				}
				return
			}
			if attrs.ScoreLabel != tc.wantLabel {
				t.Fatalf("ScoreLabel = %q, want %q", attrs.ScoreLabel, tc.wantLabel)
			}
			if attrs.Score == nil || *attrs.Score != 0 {
				t.Fatalf("Score = %v, want 0", attrs.Score)
			}
		})
	}
}

func TestRecordScoreNilEventSafe(t *testing.T) {
	t.Parallel()
	recordScore(nil, &Data{Name: "HATE"})
}
