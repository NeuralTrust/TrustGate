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

package resolver

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"net/http/httptest"
	"testing"

	appauth "github.com/NeuralTrust/TrustGate/pkg/app/auth"
	appauthmocks "github.com/NeuralTrust/TrustGate/pkg/app/auth/mocks"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func mtlsConsumer(gw *gatewaydomain.Gateway) (*appconsumer.RoutableConsumer, *authdomain.Auth) {
	auth := &authdomain.Auth{
		ID: ids.New[ids.AuthKind](), GatewayID: gw.ID, Type: authdomain.TypeMTLS, Enabled: true,
		Config: authdomain.Config{MTLS: &authdomain.MTLSConfig{CACert: "-----BEGIN CERTIFICATE-----"}},
	}
	rc := &appconsumer.RoutableConsumer{
		Consumer: &consumerdomain.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID, Type: consumerdomain.TypeLLM, Slug: "llm1234",
			Active: true, AuthIDs: []ids.AuthID{auth.ID},
		},
		Auths: []*authdomain.Auth{auth},
	}
	return rc, auth
}

// runWithXFCC runs fn inside a fiber handler for a request that carries the
// forwarded client certificate header from a peer the resolver trusts.
func runWithXFCC(t *testing.T, r *MTLSIdentityResolver, gw *gatewaydomain.Gateway, rc *appconsumer.RoutableConsumer, xfcc string) (*appauth.AuthContext, error) {
	t.Helper()
	var got *appauth.AuthContext
	var gotErr error
	app := fiber.New()
	app.Post("/*", func(c *fiber.Ctx) error {
		got, gotErr = r.Resolve(c, gw, rc)
		return c.SendStatus(fiber.StatusOK)
	})
	req := httptest.NewRequest(fiber.MethodPost, "/llm1234/v1/chat/completions", nil)
	if xfcc != "" {
		req.Header.Set(HeaderXFCC, xfcc)
	}
	_, err := app.Test(req)
	require.NoError(t, err)
	return got, gotErr
}

func TestMTLSResolver_AuthenticatesAgainstTheConsumerCA(t *testing.T) {
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	rc, auth := mtlsConsumer(gw)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "batch-runner"}, DNSNames: []string{"batch.internal"}}
	certs := appauthmocks.NewClientCertificateExtractor(t)
	certs.EXPECT().FromXFCC("Cert=...").Return(cert, nil).Once()
	validator := appauthmocks.NewMTLSValidator(t)
	validator.EXPECT().Validate(cert, auth.Config.MTLS).Return(&identity.Principal{
		Subject: "batch-runner", Method: identity.MethodMTLS,
		Claims: map[string]any{"common_name": "batch-runner", "dns_names": []string{"batch.internal"}},
	}, nil).Once()

	// fiber's test transport reports 0.0.0.0 as the peer; trust everything.
	r := NewMTLSIdentityResolver(validator, certs, []string{"0.0.0.0/0", "::/0"})
	got, err := runWithXFCC(t, r, gw, rc, "Cert=...")
	require.NoError(t, err)
	require.Equal(t, appauth.MethodMTLS, got.Method)
	require.Equal(t, auth.ID, got.AuthID)
	require.Equal(t, "batch-runner", got.Subject)
	require.NotNil(t, got.Principal)
	require.Equal(t, identity.MethodMTLS, got.Principal.Method)
	require.Equal(t, got.Claims, got.Principal.Claims)
	require.Equal(t, "batch-runner", got.Claims["common_name"])
}

func TestMTLSResolver_Rejections(t *testing.T) {
	gw := &gatewaydomain.Gateway{ID: ids.New[ids.GatewayKind](), Slug: "acme"}
	rc, _ := mtlsConsumer(gw)
	cert := &x509.Certificate{Subject: pkix.Name{CommonName: "stranger"}}

	t.Run("no certificate is unauthenticated", func(t *testing.T) {
		r := NewMTLSIdentityResolver(appauthmocks.NewMTLSValidator(t), appauthmocks.NewClientCertificateExtractor(t), []string{"0.0.0.0/0"})
		_, err := runWithXFCC(t, r, gw, rc, "")
		require.ErrorIs(t, err, ErrUnauthenticated)
	})
	t.Run("forwarded certificate from an untrusted peer is ignored", func(t *testing.T) {
		r := NewMTLSIdentityResolver(appauthmocks.NewMTLSValidator(t), appauthmocks.NewClientCertificateExtractor(t), nil)
		_, err := runWithXFCC(t, r, gw, rc, "Cert=...")
		require.ErrorIs(t, err, ErrUnauthenticated)
	})
	t.Run("certificate the CA rejects is unauthenticated", func(t *testing.T) {
		certs := appauthmocks.NewClientCertificateExtractor(t)
		certs.EXPECT().FromXFCC("Cert=...").Return(cert, nil).Once()
		validator := appauthmocks.NewMTLSValidator(t)
		validator.EXPECT().Validate(cert, mock.Anything).Return(nil, x509.UnknownAuthorityError{}).Once()
		r := NewMTLSIdentityResolver(validator, certs, []string{"0.0.0.0/0", "::/0"})
		_, err := runWithXFCC(t, r, gw, rc, "Cert=...")
		require.ErrorIs(t, err, ErrUnauthenticated)
	})
	t.Run("consumer without an mTLS anchor is forbidden", func(t *testing.T) {
		certs := appauthmocks.NewClientCertificateExtractor(t)
		certs.EXPECT().FromXFCC("Cert=...").Return(cert, nil).Once()
		r := NewMTLSIdentityResolver(appauthmocks.NewMTLSValidator(t), certs, []string{"0.0.0.0/0", "::/0"})
		plain := &appconsumer.RoutableConsumer{Consumer: &consumerdomain.Consumer{ID: ids.New[ids.ConsumerKind](), GatewayID: gw.ID}}
		_, err := runWithXFCC(t, r, gw, plain, "Cert=...")
		require.ErrorIs(t, err, ErrForbidden)
	})
}
