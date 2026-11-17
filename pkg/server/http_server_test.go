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

package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/require"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/server/router"
)

type pingRouter struct{}

func (pingRouter) BuildRoutes(app *fiber.App) error {
	app.Get("/ping", func(c *fiber.Ctx) error { return c.SendString("pong") })
	return nil
}

// writeSelfSigned writes a certificate for 127.0.0.1 and its key, and returns
// their paths and a pool that trusts the certificate.
func writeSelfSigned(t *testing.T) (certFile, keyFile string, pool *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "admin.test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	pool = x509.NewCertPool()
	pool.AddCert(cert)
	return certFile, keyFile, pool
}

func freeLoopbackAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// With WithTLS the server answers HTTPS, and a plain HTTP request to the same
// port gets no answer it can read as one.
func TestHTTPServer_ServesTLS(t *testing.T) {
	certFile, keyFile, pool := writeSelfSigned(t)
	addr := freeLoopbackAddr(t)
	srv := NewHTTPServer("admin", addr, config.ServerConfig{}, slog.New(slog.DiscardHandler),
		[]router.ServerRouter{pingRouter{}}, WithTLS(certFile, keyFile))
	go func() { _ = srv.Run() }()
	t.Cleanup(func() { _ = srv.Shutdown() })

	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}},
	}
	var resp *http.Response
	require.Eventually(t, func() bool {
		var err error
		resp, err = client.Get("https://" + addr + "/ping")
		return err == nil
	}, 5*time.Second, 20*time.Millisecond, "the server must answer HTTPS")
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	require.NoError(t, resp.Body.Close())
	require.Equal(t, "pong", string(body))
	require.NotNil(t, resp.TLS)

	plain := &http.Client{Timeout: 2 * time.Second}
	if resp, err := plain.Get("http://" + addr + "/ping"); err == nil {
		_ = resp.Body.Close()
		require.NotEqual(t, http.StatusOK, resp.StatusCode, "plain HTTP must not be served")
	}
}
