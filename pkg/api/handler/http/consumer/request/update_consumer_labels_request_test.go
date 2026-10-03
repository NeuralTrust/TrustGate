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
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func decodeLabels(t *testing.T, body string) UpdateConsumerLabelsRequest {
	t.Helper()
	var req UpdateConsumerLabelsRequest
	require.NoError(t, json.Unmarshal([]byte(body), &req))
	return req
}

func TestUpdateConsumerLabelsRequest_Validate(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "one label", body: `{"labels":[{"id":"a","name":"Billing","instructions":"refunds","examples":["refund?"]}]}`},
		{name: "empty list clears", body: `{"labels":[]}`},
		{name: "missing field", body: `{}`, wantErr: true},
		{name: "null field", body: `{"labels":null}`, wantErr: true},
		{name: "missing id", body: `{"labels":[{"name":"Billing","instructions":"refunds"}]}`, wantErr: true},
		{name: "missing instructions", body: `{"labels":[{"id":"a","name":"Billing"}]}`, wantErr: true},
		{name: "duplicated id", body: `{"labels":[{"id":"a","name":"One","instructions":"i"},{"id":"a","name":"Two","instructions":"i"}]}`, wantErr: true},
		{name: "duplicated name", body: `{"labels":[{"id":"a","name":"Billing","instructions":"i"},{"id":"b","name":"BILLING","instructions":"i"}]}`, wantErr: true},
		{name: "too many examples", body: `{"labels":[{"id":"a","name":"n","instructions":"i","examples":["1","2","3","4","5","6"]}]}`, wantErr: true},
		{name: "name too long", body: `{"labels":[{"id":"a","name":"` + strings.Repeat("n", 65) + `","instructions":"i"}]}`, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			req := decodeLabels(t, tt.body)
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

func TestUpdateConsumerLabelsRequest_TooManyLabels(t *testing.T) {
	t.Parallel()
	req := UpdateConsumerLabelsRequest{Labels: make([]ConsumerLabelRequest, 11)}
	for i := range req.Labels {
		req.Labels[i] = ConsumerLabelRequest{ID: strings.Repeat("i", i+1), Name: strings.Repeat("n", i+1), Instructions: "x"}
	}
	require.ErrorIs(t, req.Validate(), commonerrors.ErrValidation)
}

func TestUpdateConsumerLabelsRequest_ToDomainTrims(t *testing.T) {
	t.Parallel()
	req := decodeLabels(t, `{"labels":[{"id":" a ","name":" Billing ","instructions":" refunds ","examples":[" refund? "]}]}`)
	got := req.ToDomain()
	require.Len(t, got, 1)
	assert.Equal(t, "a", got[0].ID)
	assert.Equal(t, "Billing", got[0].Name)
	assert.Equal(t, "refunds", got[0].Instructions)
	assert.Equal(t, []string{"refund?"}, got[0].Examples)
}

func TestUpdateConsumerRequest_IgnoresLabels(t *testing.T) {
	t.Parallel()
	var req UpdateConsumerRequest
	require.NoError(t, json.Unmarshal([]byte(`{"name":"x","labels":[]}`), &req))
	raw, err := json.Marshal(req)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "labels", "the generic consumer update carries no labels, so it can never clear them")
}
