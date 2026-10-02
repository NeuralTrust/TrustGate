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
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
)

func selfSignedCert(t *testing.T) (tls.Certificate, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "collector"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, path
}

// operatorEnv is what prod sets for the in-cluster collector.
func operatorEnv(t *testing.T, caFile string) {
	t.Helper()
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "authorization=Bearer operator-secret")
	t.Setenv("OTEL_EXPORTER_OTLP_LOGS_HEADERS", "x-operator=1")
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://collector.svc:4318")
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", caFile)
	t.Setenv("OTEL_EXPORTER_OTLP_COMPRESSION", "gzip")
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
	s.Endpoint = strings.Replace(s.Endpoint, strings.TrimPrefix(strings.TrimPrefix(endpoint, "https://"), "http://"), stubHostPort, 1)
	netguardtest.Allow(t) // the stub is on loopback; the dial guard is covered elsewhere
	return s
}

func TestGuardedHTTPExporter_IgnoresOperatorEnv(t *testing.T) {
	_, caFile := selfSignedCert(t)
	operatorEnv(t, caFile)

	for _, endpoint := range []string{"otel.example.com:4318", "https://otel.example.com:4318"} {
		t.Run(endpoint, func(t *testing.T) {
			type seen struct {
				auth, op, enc, path string
				tls                 bool
			}
			got := make(chan seen, 4)
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got <- seen{r.Header.Get("Authorization"), r.Header.Get("X-Operator"), r.Header.Get("Content-Encoding"), r.URL.Path, r.TLS != nil}
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			s := tenantSettingsFor(t, endpoint, strings.TrimPrefix(srv.URL, "https://"))
			exp, err := newHTTPExporter(context.Background(), s)
			require.NoError(t, err)
			require.NoError(t, exp.Export(context.Background(), sampleRecords()))

			r := <-got
			require.Empty(t, r.auth, "the operator's Authorization header must not reach a tenant collector")
			require.Empty(t, r.op)
			require.True(t, r.tls, "a tenant endpoint without a scheme is https, whatever OTEL_EXPORTER_OTLP_INSECURE says")
			require.Equal(t, "/v1/logs", r.path)
			require.Empty(t, r.enc, "the tenant chose no compression; the env gzip must not apply")
		})
	}
}

type logsRecorder struct {
	collogspb.UnimplementedLogsServiceServer
	mu  sync.Mutex
	md  []metadata.MD
	hit int
}

func (l *logsRecorder) Export(ctx context.Context, _ *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	md, _ := metadata.FromIncomingContext(ctx)
	l.mu.Lock()
	l.md = append(l.md, md)
	l.hit++
	l.mu.Unlock()
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func TestGuardedGRPCExporter_IgnoresOperatorEnv(t *testing.T) {
	cert, caFile := selfSignedCert(t)
	operatorEnv(t, caFile)

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	rec := &logsRecorder{}
	srv := grpc.NewServer(grpc.Creds(credentials.NewServerTLSFromCert(&cert)))
	collogspb.RegisterLogsServiceServer(srv, rec)
	go func() { _ = srv.Serve(lis) }()
	t.Cleanup(srv.Stop)

	s := tenantSettingsFor(t, "otel.example.com:4317", lis.Addr().String())
	s.Protocol = ProtocolGRPC
	exp, err := newGRPCExporter(context.Background(), s)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	require.NoError(t, exp.Export(ctx, sampleRecords()), "the connection must be TLS even though the env says insecure")

	rec.mu.Lock()
	defer rec.mu.Unlock()
	require.Equal(t, 1, rec.hit)
	require.Empty(t, rec.md[0].Get("authorization"))
	require.Empty(t, rec.md[0].Get("x-operator"))
}
