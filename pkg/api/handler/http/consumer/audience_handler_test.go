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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	consumerhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appconsumermocks "github.com/NeuralTrust/TrustGate/pkg/app/consumer/mocks"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestConsumerHandlers_Audience(t *testing.T) {
	t.Parallel()
	gw := ids.New[ids.GatewayKind]()
	for _, tc := range []struct {
		name, method, body string
		wantStatus         int
	}{
		{name: "create defaults to application", method: http.MethodPost, body: `{"name":"chat"}`, wantStatus: http.StatusCreated},
		{name: "create ignores auths", method: http.MethodPost, body: `{"name":"chat","auths":["k"]}`, wantStatus: http.StatusCreated},
		{name: "create with an invalid audience", method: http.MethodPost, body: `{"name":"chat","audience":"team"}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "update with an invalid audience", method: http.MethodPut, body: `{"audience":"team"}`, wantStatus: http.StatusUnprocessableEntity},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			creator := appconsumermocks.NewCreator(t)
			if tc.wantStatus == http.StatusCreated {
				creator.EXPECT().Create(mock.Anything, mock.Anything).RunAndReturn(func(_ context.Context, in appconsumer.CreateInput) (*domain.Consumer, error) {
					return &domain.Consumer{GatewayID: gw, Name: in.Name, Audience: in.Audience}, nil
				}).Once()
			}
			app := fiber.New()
			app.Post("/gateways/:gateway_id/consumers", consumerhttp.NewCreateConsumerHandler(creator).Handle)
			app.Put("/gateways/:gateway_id/consumers/:id", consumerhttp.NewUpdateConsumerHandler(appconsumermocks.NewUpdater(t)).Handle)
			url := "/gateways/" + gw.String() + "/consumers"
			if tc.method == http.MethodPut {
				url += "/" + ids.New[ids.ConsumerKind]().String()
			}
			req := httptest.NewRequest(tc.method, url, strings.NewReader(tc.body))
			req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			res, err := app.Test(req)
			require.NoError(t, err)
			defer func() { _ = res.Body.Close() }()
			require.Equal(t, tc.wantStatus, res.StatusCode)
			if res.StatusCode == http.StatusCreated {
				var out map[string]any
				require.NoError(t, json.NewDecoder(res.Body).Decode(&out))
				require.Equal(t, "application", out["audience"])
			}
		})
	}
}
