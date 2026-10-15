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

package store_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	storehttp "github.com/NeuralTrust/TrustGate/pkg/api/handler/http/store"
	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	appstore "github.com/NeuralTrust/TrustGate/pkg/app/store"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

type fakeDisconnector struct {
	got *appstore.PrincipalDisconnectRequest
	err error
}

func (f *fakeDisconnector) Disconnect(_ context.Context, in appstore.PrincipalDisconnectRequest) error {
	f.got = &in
	return f.err
}

func disconnectApp(d appstore.PrincipalDisconnector, caller middleware.AdminIdentity) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		middleware.StoreAdminIdentity(c, caller)
		return c.Next()
	})
	var opts []storehttp.PrincipalHandlerOption
	if d != nil {
		opts = append(opts, storehttp.WithPrincipalDisconnector(d))
	}
	h := storehttp.NewPrincipalHandler(&fakePreview{}, nil, nil, nil, opts...)
	app.Delete("/v1/gateways/:gateway_id/store/principal/connections/:registry_id", h.Disconnect)
	return app
}

func callDisconnect(t *testing.T, app *fiber.App, gw ids.GatewayID, registryID string) (int, string) {
	t.Helper()
	res, err := app.Test(httptest.NewRequest(http.MethodDelete, "/v1/gateways/"+gw.String()+"/store/principal/connections/"+registryID, nil))
	require.NoError(t, err)
	defer func() { _ = res.Body.Close() }()
	raw, err := io.ReadAll(res.Body)
	require.NoError(t, err)
	return res.StatusCode, string(raw)
}

var portalUser = middleware.AdminIdentity{Kind: middleware.AdminIdentityHuman, TenantID: "t1", Subject: "alice"}

// The Portal revokes the caller's own account, never one named in the request.
func TestPrincipalDisconnect_RevokesTheCallersOwnAccount(t *testing.T) {
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]()
	d := &fakeDisconnector{}

	status, raw := callDisconnect(t, disconnectApp(d, portalUser), gw, reg.String())

	require.Equal(t, http.StatusNoContent, status, raw)
	require.Equal(t, &appstore.PrincipalDisconnectRequest{GatewayID: gw, PrincipalSub: "alice", RegistryID: reg}, d.got)
}

func TestPrincipalDisconnect_Refusals(t *testing.T) {
	gw, reg := ids.New[ids.GatewayKind](), ids.New[ids.RegistryKind]().String()
	service := middleware.AdminIdentity{Kind: middleware.AdminIdentityService, TenantID: "t1", Subject: "svc"}
	for name, tc := range map[string]struct {
		d        appstore.PrincipalDisconnector
		caller   middleware.AdminIdentity
		registry string
		want     int
	}{
		"a service credential":  {d: &fakeDisconnector{}, caller: service, registry: reg, want: http.StatusForbidden},
		"a malformed instance":  {d: &fakeDisconnector{}, caller: portalUser, registry: "linear", want: http.StatusUnprocessableEntity},
		"a shared account":      {d: &fakeDisconnector{err: appstore.ErrSharedConnection}, caller: portalUser, registry: reg, want: http.StatusConflict},
		"no disconnect on here": {caller: portalUser, registry: reg, want: http.StatusNotFound},
	} {
		status, raw := callDisconnect(t, disconnectApp(tc.d, tc.caller), gw, tc.registry)
		require.Equal(t, tc.want, status, "%s: %s", name, raw)
		if fake, ok := tc.d.(*fakeDisconnector); ok && tc.want != http.StatusConflict {
			require.Nil(t, fake.got, "%s: nothing must be revoked", name)
		}
	}
}
