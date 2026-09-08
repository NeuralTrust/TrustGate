package middleware_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/api/middleware"
	"github.com/NeuralTrust/TrustGate/pkg/api/resolver"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/NeuralTrust/TrustGate/pkg/domain/identity"
	"github.com/NeuralTrust/TrustGate/pkg/infra/auth/mtls"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"
)

func TestLLMMTLSMiddlewarePreservesVerifiedPrincipal(t *testing.T) {
	t.Parallel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	require.NoError(t, err)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "batch-client"}, NotBefore: ca.NotBefore, NotAfter: ca.NotAfter, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &key.PublicKey, key)
	require.NoError(t, err)
	gw, rc, _ := inlineConsumerWithAPIKey(t)
	rc.Auths[0].Type = authdomain.TypeMTLS
	rc.Auths[0].Config = authdomain.Config{MTLS: &authdomain.MTLSConfig{CACert: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}))}}
	for _, trusted := range []bool{true, false} {
		t.Run(map[bool]string{true: "trusted proxy", false: "spoofed XFCC"}[trusted], func(t *testing.T) {
			var peers []string
			if trusted {
				peers = []string{"0.0.0.0/32"}
			}
			mtlsResolver := resolver.NewMTLSIdentityResolver(mtls.NewValidator(), mtls.NewXFCCExtractor(), peers)
			authMiddleware := middleware.NewAuthMiddleware(resolver.NewIdentityResolver(nil, resolver.NewAPIKeyIdentityResolver(), nil, mtlsResolver), fakeDataFinder{data: appconsumer.NewData(gw.ID, []appconsumer.RoutableConsumer{rc})}, fakeGatewayResolver{gateway: gw}, slog.Default())
			app := fiber.New()
			called := false
			app.Post("/*", authMiddleware.Middleware(), func(c *fiber.Ctx) error {
				called = true
				p := identity.PrincipalFromContext(c.UserContext())
				require.NotNil(t, p)
				require.Equal(t, "batch-client", p.Subject)
				require.Equal(t, identity.MethodMTLS, p.Method)
				return c.SendStatus(fiber.StatusOK)
			})
			req := httptest.NewRequest(fiber.MethodPost, "/cons1234/v1/chat/completions", nil)
			req.Header.Set(resolver.HeaderXFCC, "Cert="+url.QueryEscape(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}))))
			resp, err := app.Test(req)
			require.NoError(t, err)
			require.NoError(t, resp.Body.Close())
			require.Equal(t, trusted, called)
			if trusted {
				require.Equal(t, fiber.StatusOK, resp.StatusCode)
			} else {
				require.Equal(t, fiber.StatusUnauthorized, resp.StatusCode)
			}
		})
	}
}
