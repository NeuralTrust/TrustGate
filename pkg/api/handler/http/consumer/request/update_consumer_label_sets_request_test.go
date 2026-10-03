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

package request

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const sentimentSet = `{"id":"set-1","name":"Sentiment","instructions":"overall mood","labels":[{"name":"positive","description":"happy"},{"name":"negative"}]}`

func decodeLabelSets(t *testing.T, body string) UpdateConsumerLabelSetsRequest {
	t.Helper()
	var req UpdateConsumerLabelSetsRequest
	require.NoError(t, json.Unmarshal([]byte(body), &req))
	return req
}

func labelsJSON(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"name":"label-%d"}`, i)
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func setsJSON(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`{"id":"set-%d","name":"Set %d","labels":[{"name":"a"},{"name":"b"}]}`, i, i)
	}
	return `{"label_sets":[` + strings.Join(parts, ",") + `]}`
}

func TestUpdateConsumerLabelSetsRequest_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "one set", body: `{"label_sets":[` + sentimentSet + `]}`},
		{name: "without instructions nor descriptions", body: `{"label_sets":[{"id":"a","name":"Topic","labels":[{"name":"billing"},{"name":"legal"}]}]}`},
		{name: "empty list clears", body: `{"label_sets":[]}`},
		{name: "the maximum of sets", body: setsJSON(10)},
		{name: "over the maximum of sets", body: setsJSON(11), wantErr: true},
		{name: "missing field", body: `{}`, wantErr: true},
		{name: "null field", body: `{"label_sets":null}`, wantErr: true},
		{name: "v1 labels field", body: `{"labels":[]}`, wantErr: true},
		{name: "missing id", body: `{"label_sets":[{"name":"Topic","labels":[{"name":"a"},{"name":"b"}]}]}`, wantErr: true},
		{name: "missing name", body: `{"label_sets":[{"id":"a","labels":[{"name":"a"},{"name":"b"}]}]}`, wantErr: true},
		{name: "set name too long", body: `{"label_sets":[{"id":"a","name":"` + strings.Repeat("n", 65) + `","labels":[{"name":"a"},{"name":"b"}]}]}`, wantErr: true},
		{name: "instructions too long", body: `{"label_sets":[{"id":"a","name":"n","instructions":"` + strings.Repeat("i", 2001) + `","labels":[{"name":"a"},{"name":"b"}]}]}`, wantErr: true},
		{name: "no labels", body: `{"label_sets":[{"id":"a","name":"Topic","labels":[]}]}`, wantErr: true},
		{name: "a single label", body: `{"label_sets":[{"id":"a","name":"Topic","labels":[{"name":"a"}]}]}`, wantErr: true},
		{name: "the maximum of labels", body: `{"label_sets":[{"id":"a","name":"Topic","labels":` + labelsJSON(20) + `}]}`},
		{name: "over the maximum of labels", body: `{"label_sets":[{"id":"a","name":"Topic","labels":` + labelsJSON(21) + `}]}`, wantErr: true},
		{name: "blank label name", body: `{"label_sets":[{"id":"a","name":"Topic","labels":[{"name":" "},{"name":"b"}]}]}`, wantErr: true},
		{name: "label name too long", body: `{"label_sets":[{"id":"a","name":"Topic","labels":[{"name":"` + strings.Repeat("n", 65) + `"},{"name":"b"}]}]}`, wantErr: true},
		{name: "description too long", body: `{"label_sets":[{"id":"a","name":"Topic","labels":[{"name":"a","description":"` + strings.Repeat("d", 501) + `"},{"name":"b"}]}]}`, wantErr: true},
		{name: "duplicated label names", body: `{"label_sets":[{"id":"a","name":"Topic","labels":[{"name":"Billing"},{"name":"billing"}]}]}`, wantErr: true},
		{name: "duplicated set id", body: `{"label_sets":[{"id":"a","name":"One","labels":[{"name":"a"},{"name":"b"}]},{"id":"a","name":"Two","labels":[{"name":"a"},{"name":"b"}]}]}`, wantErr: true},
		{name: "duplicated set name", body: `{"label_sets":[{"id":"a","name":"Topic","labels":[{"name":"a"},{"name":"b"}]},{"id":"b","name":"TOPIC","labels":[{"name":"a"},{"name":"b"}]}]}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := decodeLabelSets(t, tt.body)
			err := req.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, commonerrors.ErrValidation), "error %v must be a validation error", err)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestUpdateConsumerLabelSetsRequest_ToDomainTrims(t *testing.T) {
	t.Parallel()
	req := decodeLabelSets(t, `{"label_sets":[{"id":" a ","name":" Sentiment ","instructions":" mood ","labels":[{"name":" positive ","description":" happy "},{"name":"negative"}]}]}`)
	got := req.ToDomain()
	require.Len(t, got, 1)
	assert.Equal(t, "a", got[0].ID)
	assert.Equal(t, "Sentiment", got[0].Name)
	assert.Equal(t, "mood", got[0].Instructions)
	require.Len(t, got[0].Labels, 2)
	assert.Equal(t, "positive", got[0].Labels[0].Name)
	assert.Equal(t, "happy", got[0].Labels[0].Description)
	assert.Equal(t, "", got[0].Labels[1].Description)
}

func TestUpdateConsumerRequest_IgnoresLabelSets(t *testing.T) {
	t.Parallel()
	var req UpdateConsumerRequest
	require.NoError(t, json.Unmarshal([]byte(`{"name":"x","label_sets":[]}`), &req))
	raw, err := json.Marshal(req)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "label_sets", "the generic consumer update carries no label sets, so it can never clear them")
}

func TestCreateConsumerRequest_IgnoresLabelSets(t *testing.T) {
	t.Parallel()
	var req CreateConsumerRequest
	require.NoError(t, json.Unmarshal([]byte(`{"name":"x","label_sets":[`+sentimentSet+`]}`), &req))
	raw, err := json.Marshal(req)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "label_sets", "the generic consumer create carries no label sets")
}
