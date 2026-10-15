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

package consumer_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	consumerhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appconsumermocks "github.com/NeuralTrust/TrustGate/pkg/app/consumer/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/trafficlabel"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const sentimentBody = `{"label_sets":[{"id":" set-1 ","name":"Sentiment","instructions":"overall mood","labels":[{"name":"positive","description":"happy"},{"name":"negative"}]}]}`

func sentiment() trafficlabel.LabelSet {
	return trafficlabel.LabelSet{
		ID:           "set-1",
		Name:         "Sentiment",
		Instructions: "overall mood",
		Labels:       []trafficlabel.Label{{Name: "positive", Description: "happy"}, {Name: "negative"}},
	}
}

func putLabelSets(t *testing.T, updater appconsumer.LabelSetUpdater, gatewayID, consumerID, body string) (int, map[string]any) {
	t.Helper()
	app := fiber.New()
	app.Put("/v1/gateways/:gateway_id/consumers/:id/label-sets", consumerhttp.NewUpdateConsumerLabelSetsHandler(updater).Handle)
	req := httptest.NewRequest(http.MethodPut, "/v1/gateways/"+gatewayID+"/consumers/"+consumerID+"/label-sets", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	out := map[string]any{}
	require.NoError(t, json.Unmarshal(raw, &out), "body: %s", raw)
	return resp.StatusCode, out
}

func TestUpdateConsumerLabelSetsHandler_ReturnsTheFullConsumer(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	updated := &domain.Consumer{
		ID: consumerID, GatewayID: gwID, Name: "chat", Slug: "chat", Type: domain.TypeLLM, Active: true,
		LabelSets: []trafficlabel.LabelSet{sentiment()},
	}
	updater := appconsumermocks.NewLabelSetUpdater(t)
	updater.EXPECT().
		UpdateLabelSets(mock.Anything, appconsumer.UpdateLabelSetsInput{
			ID:        consumerID,
			GatewayID: gwID,
			LabelSets: []trafficlabel.LabelSet{sentiment()},
		}).
		Return(updated, nil).
		Once()

	status, body := putLabelSets(t, updater, gwID.String(), consumerID.String(), sentimentBody)

	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, consumerID.String(), body["id"])
	assert.Equal(t, "chat", body["name"])
	sets, ok := body["label_sets"].([]any)
	require.True(t, ok)
	require.Len(t, sets, 1)
	set := sets[0].(map[string]any)
	assert.Equal(t, "set-1", set["id"])
	assert.Equal(t, "Sentiment", set["name"])
	assert.Equal(t, "overall mood", set["instructions"])
	assert.Equal(t, []any{
		map[string]any{"name": "positive", "description": "happy"},
		map[string]any{"name": "negative", "description": ""},
	}, set["labels"])
	_, hasV1 := body["labels"]
	assert.False(t, hasV1, "the v1 labels field is gone")
}

func TestUpdateConsumerLabelSetsHandler_EmptyListClears(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	updater := appconsumermocks.NewLabelSetUpdater(t)
	updater.EXPECT().
		UpdateLabelSets(mock.Anything, mock.MatchedBy(func(in appconsumer.UpdateLabelSetsInput) bool { return len(in.LabelSets) == 0 })).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: domain.TypeLLM}, nil).
		Once()

	status, body := putLabelSets(t, updater, gwID.String(), consumerID.String(), `{"label_sets":[]}`)

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, []any{}, body["label_sets"], "a consumer without label sets answers an empty list")
}

func TestUpdateConsumerLabelSetsHandler_RejectsBeforeTheUseCase(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]().String()
	consumerID := ids.New[ids.ConsumerKind]().String()
	tests := []struct {
		name       string
		gateway    string
		consumer   string
		body       string
		wantStatus int
	}{
		{name: "missing label_sets", gateway: gwID, consumer: consumerID, body: `{}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "null label_sets", gateway: gwID, consumer: consumerID, body: `{"label_sets":null}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "missing body", gateway: gwID, consumer: consumerID, body: ``, wantStatus: http.StatusUnprocessableEntity},
		{name: "invalid json", gateway: gwID, consumer: consumerID, body: `{`, wantStatus: http.StatusUnprocessableEntity},
		{
			name: "duplicated label names", gateway: gwID, consumer: consumerID,
			body:       `{"label_sets":[{"id":"a","name":"Topic","labels":[{"name":"X"},{"name":"x"}]}]}`,
			wantStatus: http.StatusUnprocessableEntity,
		},
		{
			name: "a single label", gateway: gwID, consumer: consumerID,
			body:       `{"label_sets":[{"id":"a","name":"Topic","labels":[{"name":"X"}]}]}`,
			wantStatus: http.StatusUnprocessableEntity,
		},
		{name: "bad consumer id", gateway: gwID, consumer: "nope", body: `{"label_sets":[]}`, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			status, _ := putLabelSets(t, appconsumermocks.NewLabelSetUpdater(t), tt.gateway, tt.consumer, tt.body)
			assert.Equal(t, tt.wantStatus, status)
		})
	}
}

func TestUpdateConsumerLabelSetsHandler_MapsUseCaseErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "unknown consumer", err: domain.ErrNotFound, wantStatus: http.StatusNotFound},
		{name: "MCP consumer", err: domain.ErrInvalidLabelSets, wantStatus: http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			updater := appconsumermocks.NewLabelSetUpdater(t)
			updater.EXPECT().UpdateLabelSets(mock.Anything, mock.Anything).Return(nil, tt.err).Once()
			status, _ := putLabelSets(t, updater, ids.New[ids.GatewayKind]().String(), ids.New[ids.ConsumerKind]().String(), sentimentBody)
			assert.Equal(t, tt.wantStatus, status)
		})
	}
}
