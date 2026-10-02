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

package otlp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

func selfSignedCert(t *testing.T) (cert tls.Certificate, certFile, keyFile string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "collector"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem")
	require.NoError(t, os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	require.NoError(t, os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, certFile, keyFile
}

// operatorEnv sets every OTEL_EXPORTER_OTLP_* variable the SDK reads, as prod
// does for the in-cluster collector, plus an HTTP proxy. TIMEOUT=1 (a
// millisecond) is a canary: if it applied, no export could succeed.
func operatorEnv(t *testing.T, certFile, keyFile string) (proxyHits *atomic.Int32) {
	t.Helper()
	proxy, hits := netguardtest.Hostile(t, nil)
	for _, p := range []string{"OTEL_EXPORTER_OTLP_", "OTEL_EXPORTER_OTLP_LOGS_"} {
		t.Setenv(p+"ENDPOINT", "http://collector.svc:4318")
		t.Setenv(p+"INSECURE", "true")
		t.Setenv(p+"HEADERS", "authorization=Bearer%20operator-secret,x-operator=1")
		t.Setenv(p+"CERTIFICATE", certFile)
		t.Setenv(p+"CLIENT_CERTIFICATE", certFile)
		t.Setenv(p+"CLIENT_KEY", keyFile)
		t.Setenv(p+"COMPRESSION", "gzip")
		t.Setenv(p+"TIMEOUT", "1")
	}
	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		t.Setenv(k, proxy.URL)
	}
	return hits
}

// tenantSettingsFor returns what the tenant policy builds for endpoint, with the
// host swapped for the stub's so the test can reach it.
func tenantSettingsFor(t *testing.T, endpoint, stubHostPort string) Settings {
	t.Helper()
	netguardtest.Deny(t)
	tpl := NewTemplate(testLogger(), config.OTLPConfig{
		Endpoint: "http://collector.svc:4318/v1/logs", Insecure: true, Protocol: "http/protobuf",
		Headers: map[string]string{"authorization": "Bearer operator-secret"},
	})
	s, err := tpl.tenantSettings(map[string]interface{}{
		"endpoint": endpoint, "tls": map[string]interface{}{"skip_verify": true}, "timeout": "3s", "compression": "none",
	})
	require.NoError(t, err)
	require.True(t, s.guarded)
	host := endpoint
	if u, perr := url.Parse(endpoint); perr == nil && u.Host != "" {
		host = u.Host
	}
	s.Endpoint = strings.Replace(s.Endpoint, host, stubHostPort, 1)
	netguardtest.Allow(t) // the stub is on loopback; the dial guard is covered elsewhere
	return s
}

// httpCases: a bare host and an https URL must be TLS; an http URL (any case) is
// plaintext because the tenant said so. In every case nothing of the operator's
// may be sent or presented.
var httpCases = []struct {
	name, endpoint string
	wantTLS        bool
}{
	{"bare host is https", "otel.example.com:4318", true},
	{"https URL", "https://otel.example.com:4318", true},
	{"http URL", "http://otel.example.com:4318", false},
	{"upper-case HTTP URL", "HTTP://otel.example.com:4318", false},
}

func TestGuardedHTTPExporter_IgnoresOperatorEnv(t *testing.T) {
	_, certFile, keyFile := selfSignedCert(t)

	for _, tc := range httpCases {
		t.Run(tc.name, func(t *testing.T) {
			proxyHits := operatorEnv(t, certFile, keyFile)
			type seen struct {
				auth, op, enc, path string
				tls                 bool
				peerCerts           int
			}
			got := make(chan seen, 4)
			handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				v := seen{auth: r.Header.Get("Authorization"), op: r.Header.Get("X-Operator"), enc: r.Header.Get("Content-Encoding"), path: r.URL.Path}
				if r.TLS != nil {
					v.tls, v.peerCerts = true, len(r.TLS.PeerCertificates)
				}
				got <- v
				w.WriteHeader(http.StatusOK)
			})
			var srv *httptest.Server
			var hostPort string
			if tc.wantTLS {
				srv = httptest.NewUnstartedServer(handler)
				srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
				srv.StartTLS()
				hostPort = strings.TrimPrefix(srv.URL, "https://")
			} else {
				srv = httptest.NewServer(handler)
				hostPort = strings.TrimPrefix(srv.URL, "http://")
			}
			defer srv.Close()

			s := tenantSettingsFor(t, tc.endpoint, hostPort)
			exp, err := newHTTPExporter(context.Background(), s)
			require.NoError(t, err)
			require.NoError(t, exp.Export(context.Background(), sampleRecords()),
				"the operator's 1ms timeout and unreachable env endpoint must not apply")

			r := <-got
			require.Empty(t, r.auth, "the operator's Authorization header must not reach a tenant collector")
			require.Empty(t, r.op)
			require.Equal(t, tc.wantTLS, r.tls)
			require.Zero(t, r.peerCerts, "the operator's client certificate must not be presented")
			require.Equal(t, "/v1/logs", r.path)
			require.Empty(t, r.enc, "the tenant chose no compression; the env gzip must not apply")
			require.Zero(t, proxyHits.Load(), "HTTP_PROXY must not carry tenant telemetry")
		})
	}
}

type logsRecorder struct {
	collogspb.UnimplementedLogsServiceServer
	mu        sync.Mutex
	md        []metadata.MD
	peerCerts int
	tls       bool
}

func (l *logsRecorder) Export(ctx context.Context, _ *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.md = append(l.md, md)
	if p, ok := peer.FromContext(ctx); ok {
		if info, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			l.tls = true
			l.peerCerts = len(info.State.PeerCertificates)
		}
	}
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func TestGuardedGRPCExporter_IgnoresOperatorEnv(t *testing.T) {
	cert, certFile, keyFile := selfSignedCert(t)

	for _, tc := range httpCases {
		t.Run(tc.name, func(t *testing.T) {
			operatorEnv(t, certFile, keyFile)
			lis, err := net.Listen("tcp", "127.0.0.1:0")
			require.NoError(t, err)
			rec := &logsRecorder{}
			var srv *grpc.Server
			if tc.wantTLS {
				srv = grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
					Certificates: []tls.Certificate{cert}, ClientAuth: tls.RequestClientCert,
				})))
			} else {
				srv = grpc.NewServer()
			}
			collogspb.RegisterLogsServiceServer(srv, rec)
			go func() { _ = srv.Serve(lis) }()
			t.Cleanup(srv.Stop)

			endpoint := strings.Replace(tc.endpoint, ":4318", ":4317", 1)
			s := tenantSettingsFor(t, endpoint, lis.Addr().String())
			s.Protocol = ProtocolGRPC
			exp, err := newGRPCExporter(context.Background(), s)
			require.NoError(t, err)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			require.NoError(t, exp.Export(ctx, sampleRecords()))

			rec.mu.Lock()
			defer rec.mu.Unlock()
			require.Len(t, rec.md, 1)
			require.Equal(t, tc.wantTLS, rec.tls)
			require.Zero(t, rec.peerCerts, "the operator's client certificate must not be presented")
			require.Empty(t, rec.md[0].Get("authorization"))
			require.Empty(t, rec.md[0].Get("x-operator"))
		})
	}
}
