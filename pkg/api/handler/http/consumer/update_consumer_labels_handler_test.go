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

func putLabels(t *testing.T, updater appconsumer.LabelUpdater, gatewayID, consumerID, body string) (int, map[string]any) {
	t.Helper()
	app := fiber.New()
	app.Put("/v1/gateways/:gateway_id/consumers/:id/labels", consumerhttp.NewUpdateConsumerLabelsHandler(updater).Handle)
	req := httptest.NewRequest(http.MethodPut, "/v1/gateways/"+gatewayID+"/consumers/"+consumerID+"/labels", bytes.NewBufferString(body))
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

func TestUpdateConsumerLabelsHandler_ReturnsTheFullConsumer(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	updated := &domain.Consumer{
		ID: consumerID, GatewayID: gwID, Name: "chat", Slug: "chat", Type: domain.TypeLLM, Active: true,
		Labels: []trafficlabel.Label{{ID: "l-1", Name: "Billing", Instructions: "refunds"}},
	}
	updater := appconsumermocks.NewLabelUpdater(t)
	updater.EXPECT().
		UpdateLabels(mock.Anything, appconsumer.UpdateLabelsInput{
			ID:        consumerID,
			GatewayID: gwID,
			Labels:    []trafficlabel.Label{{ID: "l-1", Name: "Billing", Instructions: "refunds"}},
		}).
		Return(updated, nil).
		Once()

	status, body := putLabels(t, updater, gwID.String(), consumerID.String(),
		`{"labels":[{"id":" l-1 ","name":"Billing","instructions":"refunds"}]}`)

	require.Equal(t, http.StatusOK, status, "%v", body)
	assert.Equal(t, consumerID.String(), body["id"])
	assert.Equal(t, "chat", body["name"])
	labels, ok := body["labels"].([]any)
	require.True(t, ok)
	require.Len(t, labels, 1)
	label := labels[0].(map[string]any)
	assert.Equal(t, "l-1", label["id"])
	assert.Equal(t, []any{}, label["examples"], "examples is always a list")
}

func TestUpdateConsumerLabelsHandler_EmptyListClears(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	consumerID := ids.New[ids.ConsumerKind]()
	updater := appconsumermocks.NewLabelUpdater(t)
	updater.EXPECT().
		UpdateLabels(mock.Anything, mock.MatchedBy(func(in appconsumer.UpdateLabelsInput) bool { return len(in.Labels) == 0 })).
		Return(&domain.Consumer{ID: consumerID, GatewayID: gwID, Type: domain.TypeLLM}, nil).
		Once()

	status, body := putLabels(t, updater, gwID.String(), consumerID.String(), `{"labels":[]}`)

	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, []any{}, body["labels"], "a consumer without labels answers an empty list")
}

func TestUpdateConsumerLabelsHandler_RejectsBeforeTheUseCase(t *testing.T) {
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
		{name: "missing labels", gateway: gwID, consumer: consumerID, body: `{}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "invalid json", gateway: gwID, consumer: consumerID, body: `{`, wantStatus: http.StatusUnprocessableEntity},
		{name: "duplicated names", gateway: gwID, consumer: consumerID, body: `{"labels":[{"id":"a","name":"X","instructions":"i"},{"id":"b","name":"x","instructions":"i"}]}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "bad consumer id", gateway: gwID, consumer: "nope", body: `{"labels":[]}`, wantStatus: http.StatusBadRequest},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			status, _ := putLabels(t, appconsumermocks.NewLabelUpdater(t), tt.gateway, tt.consumer, tt.body)
			assert.Equal(t, tt.wantStatus, status)
		})
	}
}

func TestUpdateConsumerLabelsHandler_MapsUseCaseErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{name: "unknown consumer", err: domain.ErrNotFound, wantStatus: http.StatusNotFound},
		{name: "MCP consumer", err: domain.ErrInvalidLabels, wantStatus: http.StatusUnprocessableEntity},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			updater := appconsumermocks.NewLabelUpdater(t)
			updater.EXPECT().UpdateLabels(mock.Anything, mock.Anything).Return(nil, tt.err).Once()
			status, _ := putLabels(t, updater, ids.New[ids.GatewayKind]().String(), ids.New[ids.ConsumerKind]().String(),
				`{"labels":[{"id":"a","name":"Billing","instructions":"refunds"}]}`)
			assert.Equal(t, tt.wantStatus, status)
		})
	}
}
