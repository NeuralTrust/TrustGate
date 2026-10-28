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

package configsync_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	configsynchttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsync"
	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/httpio"
	revokermocks "github.com/NeuralTrust/TrustGate/pkg/app/configsyncrevocation/mocks"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const revokeRoute = "/v1/gateways/:gateway_id/config-sync/revocations"

func newRevokeApp(revoker *revokermocks.Revoker) *fiber.App {
	app := fiber.New()
	app.Post(revokeRoute, configsynchttp.NewRevokeTokensHandler(revoker).Handle)
	return app
}

func postRevoke(t *testing.T, app *fiber.App, path, body string) (int, httpio.ErrorBody) {
	t.Helper()
	req := httptest.NewRequest(fiber.MethodPost, path, strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	resp, err := app.Test(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	var out httpio.ErrorBody
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &out)
	}
	return resp.StatusCode, out
}

func TestRevokeTokensHandler_ValidBodyIs204AndPassesArguments(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	revoker := revokermocks.NewRevoker(t)
	revoker.EXPECT().Revoke(mock.Anything, gatewayID.String(), []string{"a1"}, int64(1000)).Return(nil).Once()
	app := newRevokeApp(revoker)

	status, _ := postRevoke(t, app, "/v1/gateways/"+gatewayID.String()+"/config-sync/revocations",
		`{"jtis":["a1"],"issued_before":1000}`)
	require.Equal(t, fiber.StatusNoContent, status)
}

func TestRevokeTokensHandler_MarkOnlyPassesNoJTIs(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	revoker := revokermocks.NewRevoker(t)
	revoker.EXPECT().Revoke(mock.Anything, gatewayID.String(), []string(nil), int64(1000)).Return(nil).Once()
	app := newRevokeApp(revoker)

	status, _ := postRevoke(t, app, "/v1/gateways/"+gatewayID.String()+"/config-sync/revocations",
		`{"issued_before":1000}`)
	require.Equal(t, fiber.StatusNoContent, status)
}

func TestRevokeTokensHandler_InvalidBodyIs422AndNeverReachesTheUseCase(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	app := newRevokeApp(revokermocks.NewRevoker(t))
	path := "/v1/gateways/" + gatewayID.String() + "/config-sync/revocations"

	for _, body := range []string{`{}`, `{"jtis":[]}`, `{"jtis":[""]}`, `{"issued_before":0}`, `{"jtis":`} {
		t.Run(body, func(t *testing.T) {
			status, out := postRevoke(t, app, path, body)
			require.Equal(t, fiber.StatusUnprocessableEntity, status)
			require.Equal(t, "validation_failed", out.Error)
		})
	}
}

func TestRevokeTokensHandler_UseCaseValidationIs422(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	revoker := revokermocks.NewRevoker(t)
	revoker.EXPECT().Revoke(mock.Anything, gatewayID.String(), []string(nil), int64(2000000000)).
		Return(fmt.Errorf("too far ahead: %w", commonerrors.ErrValidation)).Once()
	app := newRevokeApp(revoker)

	status, out := postRevoke(t, app, "/v1/gateways/"+gatewayID.String()+"/config-sync/revocations",
		`{"issued_before":2000000000}`)
	require.Equal(t, fiber.StatusUnprocessableEntity, status)
	require.Equal(t, "validation_failed", out.Error)
}

func TestRevokeTokensHandler_StoreFailureIs500(t *testing.T) {
	gatewayID := ids.New[ids.GatewayKind]()
	revoker := revokermocks.NewRevoker(t)
	revoker.EXPECT().Revoke(mock.Anything, gatewayID.String(), []string{"a1"}, int64(0)).
		Return(errors.New("connection refused")).Once()
	app := newRevokeApp(revoker)

	status, out := postRevoke(t, app, "/v1/gateways/"+gatewayID.String()+"/config-sync/revocations",
		`{"jtis":["a1"]}`)
	require.Equal(t, fiber.StatusInternalServerError, status)
	require.Equal(t, "internal_error", out.Error)
}

func TestRevokeTokensHandler_MalformedGatewayIDIs400(t *testing.T) {
	app := newRevokeApp(revokermocks.NewRevoker(t))

	status, out := postRevoke(t, app, "/v1/gateways/not-a-uuid/config-sync/revocations", `{"jtis":["a1"]}`)
	require.Equal(t, fiber.StatusBadRequest, status)
	require.Equal(t, "invalid_uuid", out.Error)
}
