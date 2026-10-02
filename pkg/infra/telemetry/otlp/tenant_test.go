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
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard/netguardtest"
	"github.com/stretchr/testify/require"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

func sampleRecords() []sdklog.Record {
	var r sdklog.Record
	r.SetTimestamp(time.Now())
	return []sdklog.Record{r}
}

func guardedSettings(endpoint string, protocol Protocol) Settings {
	return Settings{
		Endpoint: endpoint, Protocol: protocol, Signal: SignalLogs, Insecure: true,
		Timeout: 2 * time.Second, Compression: compressionNone, MaxBodyBytes: 4096, guarded: true,
	}
}

func TestGuardedHTTPExporter_RefusesInternalCollector(t *testing.T) {
	netguardtest.Deny(t)
	srv, hits := netguardtest.Hostile(t, func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	exp, err := newHTTPExporter(context.Background(), guardedSettings(srv.URL, ProtocolHTTP))
	require.NoError(t, err)
	require.Error(t, exp.Export(context.Background(), sampleRecords()))
	require.Zero(t, hits.Load(), "a tenant-chosen collector on a private address must never be reached")

	// Positive control: the operator's own (unguarded) exporter reaches it.
	s := guardedSettings(srv.URL, ProtocolHTTP)
	s.guarded = false
	exp, err = newHTTPExporter(context.Background(), s)
	require.NoError(t, err)
	require.NoError(t, exp.Export(context.Background(), sampleRecords()))
	require.EqualValues(t, 1, hits.Load())
}

func TestGuardedGRPCExporter_RefusesInternalCollector(t *testing.T) {
	netguardtest.Deny(t)
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = lis.Close() })
	var accepted atomic.Int32
	go func() {
		for {
			c, aerr := lis.Accept()
			if aerr != nil {
				return
			}
			accepted.Add(1)
			_ = c.Close()
		}
	}()

	exp, err := newGRPCExporter(context.Background(), guardedSettings(lis.Addr().String(), ProtocolGRPC))
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.Error(t, exp.Export(ctx, sampleRecords()))
	require.Zero(t, accepted.Load(), "the gRPC dialer must be guarded")

	s := guardedSettings(lis.Addr().String(), ProtocolGRPC)
	s.guarded = false
	exp, err = newGRPCExporter(context.Background(), s)
	require.NoError(t, err)
	ctx2, cancel2 := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel2()
	_ = exp.Export(ctx2, sampleRecords())
	require.NotZero(t, accepted.Load(), "positive control: unguarded exporter connects")
}

func TestTenantSettings_Policy(t *testing.T) {
	file := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))
	missing := filepath.Join(t.TempDir(), "missing.pem")
	tpl := NewTemplate(testLogger(), config.OTLPConfig{Endpoint: "http://collector.svc.cluster.local:4318/v1/logs"})

	t.Run("tls file paths are refused with one message whether or not the file exists", func(t *testing.T) {
		netguardtest.Deny(t)
		errExisting := tpl.ValidateTenantConfig(map[string]interface{}{
			"endpoint": "https://otel.example.com:4318", "tls": map[string]interface{}{"ca_file": file},
		})
		errMissing := tpl.ValidateTenantConfig(map[string]interface{}{
			"endpoint": "https://otel.example.com:4318", "tls": map[string]interface{}{"ca_file": missing},
		})
		require.ErrorIs(t, errExisting, errTenantTLSFiles)
		require.ErrorIs(t, errMissing, errTenantTLSFiles)
		require.Equal(t, errExisting.Error(), errMissing.Error())
		require.NotContains(t, errMissing.Error(), missing)
	})

	t.Run("a self-hosted gateway keeps tls file paths", func(t *testing.T) {
		netguardtest.Allow(t)
		require.NoError(t, tpl.ValidateTenantConfig(map[string]interface{}{
			"endpoint": "https://otel.example.com:4318", "tls": map[string]interface{}{"ca_file": file},
		}))
	})

	t.Run("operator settings keep tls file paths", func(t *testing.T) {
		netguardtest.Deny(t)
		require.NoError(t, tpl.ValidateConfig(map[string]interface{}{
			"endpoint": "https://otel.example.com:4318", "tls": map[string]interface{}{"ca_file": file},
		}))
	})

	endpoints := []struct {
		name     string
		endpoint string
		wantErr  bool
	}{
		{"public https", "https://otel.example.com:4318", false},
		{"bare public host", "otel.example.com:4317", false},
		{"loopback literal", "http://127.0.0.1:4318", true},
		{"metadata literal", "http://169.254.169.254/latest", true},
		{"private literal bare", "10.0.0.5:4317", true},
		{"localhost", "localhost:4317", true},
		{"ipv6 loopback", "http://[::1]:4318", true},
		{"unix scheme", "unix:///var/run/x.sock", true},
		{"file scheme", "file:///etc/passwd", true},
		{"credentials in url", "https://user:pw@otel.example.com", true},
	}
	for _, tt := range endpoints {
		t.Run("endpoint "+tt.name, func(t *testing.T) {
			netguardtest.Deny(t)
			err := tpl.ValidateTenantConfig(map[string]interface{}{"endpoint": tt.endpoint})
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}

	t.Run("a tenant that names no endpoint inherits the operator collector unguarded", func(t *testing.T) {
		netguardtest.Deny(t)
		s, err := tpl.tenantSettings(map[string]interface{}{})
		require.NoError(t, err)
		require.False(t, s.guarded)
		require.Equal(t, "http://collector.svc.cluster.local:4318/v1/logs", s.Endpoint)
	})

	t.Run("a tenant endpoint is guarded", func(t *testing.T) {
		netguardtest.Deny(t)
		s, err := tpl.tenantSettings(map[string]interface{}{"endpoint": "https://otel.example.com:4318"})
		require.NoError(t, err)
		require.True(t, s.guarded)
	})

	t.Run("operator settings may point at the in-cluster collector", func(t *testing.T) {
		netguardtest.Deny(t)
		require.NoError(t, tpl.ValidateConfig(map[string]interface{}{"endpoint": "http://10.0.0.5:4318/v1/logs"}))
	})

	t.Run("key case does not hide a tenant endpoint", func(t *testing.T) {
		netguardtest.Deny(t)
		for _, key := range []string{"endpoint", "Endpoint", "ENDPOINT"} {
			require.Error(t, tpl.ValidateTenantConfig(map[string]interface{}{key: "http://10.0.0.5:4318"}), key)
			s, err := tpl.tenantSettings(map[string]interface{}{key: "https://otel.example.com:4318"})
			require.NoError(t, err, key)
			require.True(t, s.guarded, key)
		}
	})

	t.Run("key case does not hide tls file paths", func(t *testing.T) {
		netguardtest.Deny(t)
		err := tpl.ValidateTenantConfig(map[string]interface{}{
			"Endpoint": "https://otel.example.com:4318", "TLS": map[string]interface{}{"Ca_File": file},
		})
		require.ErrorIs(t, err, errTenantTLSFiles)
	})

	t.Run("an inherited endpoint keeps the operator's transport settings", func(t *testing.T) {
		netguardtest.Deny(t)
		op := NewTemplate(testLogger(), config.OTLPConfig{
			Endpoint: "https://collector.svc:4318/v1/logs", Protocol: "http/protobuf",
			Headers: map[string]string{"authorization": "operator"},
		})
		s, err := op.tenantSettings(map[string]interface{}{
			"headers": map[string]interface{}{"x-evil": "1"}, "insecure": true,
			"protocol": "grpc", "compression": "none", "timeout": "3s",
			"tls": map[string]interface{}{"skip_verify": true},
		})
		require.NoError(t, err)
		require.False(t, s.guarded)
		require.Equal(t, map[string]string{"authorization": "operator"}, s.Headers)
		require.False(t, s.Insecure)
		require.Nil(t, s.TLS)
		require.Equal(t, ProtocolHTTP, s.Protocol)
		require.Equal(t, "none", s.Compression)
		require.Equal(t, 3*time.Second, s.Timeout)
	})
}
