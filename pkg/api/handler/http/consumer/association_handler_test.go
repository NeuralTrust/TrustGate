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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	consumerhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/consumer"
	appconsumermocks "github.com/NeuralTrust/TrustGate/pkg/app/consumer/mocks"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestAssociationHandler_AttachAuth(t *testing.T) {
	t.Parallel()
	grantedAt := time.Date(2026, time.October, 1, 9, 0, 0, 0, time.UTC)
	const valid = `{"level":"group","granted_at":"2026-10-01T09:00:00Z"}`
	groupLink := &domain.AuthLink{Level: domain.GrantLevelGroup, Priority: domain.DefaultGrantPriority, GrantedAt: grantedAt}
	for _, tc := range []struct {
		name       string
		body       string
		attach     bool
		wantLink   *domain.AuthLink
		attachErr  error
		wantStatus int
	}{
		{name: "empty body", attach: true, wantStatus: http.StatusNoContent},
		{name: "whitespace-only body", body: " \n\t ", attach: true, wantStatus: http.StatusNoContent},
		{name: "empty object", body: `{}`, attach: true, wantStatus: http.StatusNoContent},
		{name: "priority defaults to 1", body: valid, attach: true, wantLink: groupLink, wantStatus: http.StatusNoContent},
		{name: "explicit priority zero", body: `{"level":"user","priority":0,"granted_at":"2026-10-01T11:00:00+02:00"}`, attach: true,
			wantLink: &domain.AuthLink{Level: domain.GrantLevelUser, GrantedAt: grantedAt}, wantStatus: http.StatusNoContent},
		{name: "missing level is refused by the use case", body: `{"granted_at":"2026-10-01T09:00:00Z"}`, attach: true,
			wantLink: &domain.AuthLink{Priority: domain.DefaultGrantPriority, GrantedAt: grantedAt}, attachErr: domain.ErrInvalidAuthLink, wantStatus: http.StatusUnprocessableEntity},
		{name: "missing granted_at is refused by the use case", body: `{"level":"group","priority":2}`, attach: true,
			wantLink: &domain.AuthLink{Level: domain.GrantLevelGroup, Priority: 2}, attachErr: domain.ErrInvalidAuthLink, wantStatus: http.StatusUnprocessableEntity},
		{name: "granted_at not RFC 3339", body: `{"level":"group","granted_at":"2026-10-01"}`, wantStatus: http.StatusUnprocessableEntity},
		{name: "malformed body", body: `{`, wantStatus: http.StatusUnprocessableEntity},
		{name: "link on an application consumer", body: valid, attach: true, wantLink: groupLink, attachErr: domain.ErrInvalidAuthLink, wantStatus: http.StatusUnprocessableEntity},
		{name: "audience mismatch", attach: true, attachErr: domain.ErrAudienceMismatch, wantStatus: http.StatusUnprocessableEntity},
		{name: "auth of another gateway wins over a bad link", body: `{"granted_at":"2026-10-01T09:00:00Z"}`, attach: true,
			wantLink: &domain.AuthLink{Priority: domain.DefaultGrantPriority, GrantedAt: grantedAt}, attachErr: authdomain.ErrNotFound, wantStatus: http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			gw, consumerID, authID := ids.New[ids.GatewayKind](), ids.New[ids.ConsumerKind](), ids.New[ids.AuthKind]()
			associator := appconsumermocks.NewAssociator(t)
			if tc.attach {
				associator.EXPECT().AttachAuth(mock.Anything, gw, consumerID, authID, tc.wantLink).Return(tc.attachErr).Once()
			}
			app := fiber.New()
			app.Post("/gateways/:gateway_id/consumers/:id/auths/:auth_id", consumerhttp.NewAssociationHandler(associator, nil).AttachAuth)
			req := httptest.NewRequest(http.MethodPost, "/gateways/"+gw.String()+"/consumers/"+consumerID.String()+"/auths/"+authID.String(), strings.NewReader(tc.body))
			if tc.body != "" {
				req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
			}
			res, err := app.Test(req)
			require.NoError(t, err)
			defer func() { _ = res.Body.Close() }()
			require.Equal(t, tc.wantStatus, res.StatusCode)
			if res.StatusCode == http.StatusNoContent {
				body, err := io.ReadAll(res.Body)
				require.NoError(t, err)
				require.Empty(t, body)
			}
		})
	}
}
