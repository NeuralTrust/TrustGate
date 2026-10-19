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

package auth_test

import (
	"log/slog"
	"net/http"
	"strings"
	"testing"

	authhttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/auth"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func subjectGroupsApp(sessions *recordingSessions, identity middleware.AdminIdentity) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		middleware.StoreAdminIdentity(c, identity)
		return c.Next()
	})
	app.Put("/gateways/:gateway_id/subjects/:user_id/groups", authhttp.NewUpdateSubjectGroupsHandler(sessions, slog.New(slog.DiscardHandler)).Handle)
	return app
}

func TestUpdateSubjectGroups_NoSessionsIsSuccess(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	sessions := &recordingSessions{}
	identity := middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "team-1", Subject: "admin"}
	status, raw := doJSON(t, subjectGroupsApp(sessions, identity), http.MethodPut,
		"/gateways/"+gwID.String()+"/subjects/user-1/groups", `{"groups":[" eng ","eng"]}`)
	require.Equal(t, http.StatusOK, status, raw)
	require.Contains(t, raw, `"updated":0`)
	require.Equal(t, 1, sessions.calls)
	require.True(t, sessions.wrote)
	require.Equal(t, "team-1", sessions.org)
	require.Equal(t, gwID.String(), sessions.gateway)
	require.Equal(t, "user-1", sessions.subject)
	require.Equal(t, []string{"eng"}, sessions.groups)
}

func TestUpdateSubjectGroups_RefusesWithoutATenantOrAPlainUserID(t *testing.T) {
	t.Parallel()
	gwID := ids.New[ids.GatewayKind]()
	sessions := &recordingSessions{}
	status, raw := doJSON(t, subjectGroupsApp(sessions, middleware.AdminIdentity{Kind: middleware.AdminIdentityPlatform}), http.MethodPut,
		"/gateways/"+gwID.String()+"/subjects/user-1/groups", `{"groups":["eng"]}`)
	require.Equal(t, http.StatusForbidden, status, raw)
	require.Zero(t, sessions.calls)

	status, raw = doJSON(t, subjectGroupsApp(sessions, middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "team-1"}), http.MethodPut,
		"/gateways/"+gwID.String()+"/subjects/"+strings.Repeat("a", 257)+"/groups", `{"groups":["eng"]}`)
	require.Equal(t, http.StatusUnprocessableEntity, status, raw)
	require.Zero(t, sessions.calls)
}
