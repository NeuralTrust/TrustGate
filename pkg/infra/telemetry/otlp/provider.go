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
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.41.0"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"github.com/NeuralTrust/TrustGate/pkg/infra/netguard"
)

const (
	batchMaxQueueSize = 2048
	serviceName       = "trustgate"
)

// newLoggerProvider builds a dedicated logs provider for the given settings. The
// OTLP client connects lazily, so an unreachable Collector never blocks
// construction; only hard config errors (such as unreadable TLS files) return an
// error. It never installs or reads the OTel global LoggerProvider.
func newLoggerProvider(ctx context.Context, s Settings) (*sdklog.LoggerProvider, error) {
	exporter, err := newLogExporter(ctx, s)
	if err != nil {
		return nil, err
	}
	processor := sdklog.NewBatchProcessor(exporter,
		sdklog.WithMaxQueueSize(batchMaxQueueSize),
		sdklog.WithExportTimeout(s.Timeout),
	)
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(processor),
		sdklog.WithResource(newResource()),
		sdklog.WithAttributeValueLengthLimit(s.MaxBodyBytes),
	)
	return provider, nil
}

func newResource() *resource.Resource {
	return resource.NewWithAttributes(semconv.SchemaURL, semconv.ServiceNameKey.String(serviceName))
}

func newLogExporter(ctx context.Context, s Settings) (sdklog.Exporter, error) {
	if s.Protocol == ProtocolHTTP {
		return newHTTPExporter(ctx, s)
	}
	return newGRPCExporter(ctx, s)
}

func newGRPCExporter(ctx context.Context, s Settings) (sdklog.Exporter, error) {
	opts := []otlploggrpc.Option{otlploggrpc.WithTimeout(s.Timeout)}
	if hasScheme(s.Endpoint) {
		opts = append(opts, otlploggrpc.WithEndpointURL(s.Endpoint))
	} else {
		opts = append(opts, otlploggrpc.WithEndpoint(s.Endpoint))
	}
	if len(s.Headers) > 0 {
		opts = append(opts, otlploggrpc.WithHeaders(s.Headers))
	}
	if s.Compression == compressionGzip {
		opts = append(opts, otlploggrpc.WithCompressor(compressionGzip))
	}
	if s.guarded {
		opts = append(opts, otlploggrpc.WithDialOption(grpc.WithContextDialer(guardedGRPCDialer)))
	}
	if s.Insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	} else if s.TLS != nil {
		tlsCfg, err := buildTLSConfig(s.TLS)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlploggrpc.WithTLSCredentials(credentials.NewTLS(tlsCfg)))
	}
	return otlploggrpc.New(ctx, opts...)
}

func newHTTPExporter(ctx context.Context, s Settings) (sdklog.Exporter, error) {
	opts := []otlploghttp.Option{otlploghttp.WithTimeout(s.Timeout)}
	if hasScheme(s.Endpoint) {
		opts = append(opts, otlploghttp.WithEndpointURL(withLogsPath(s.Endpoint)))
	} else {
		host, path := splitEndpoint(s.Endpoint)
		opts = append(opts, otlploghttp.WithEndpoint(host))
		if strings.Trim(path, "/") != "" {
			opts = append(opts, otlploghttp.WithURLPath(path))
		}
	}
	if len(s.Headers) > 0 {
		opts = append(opts, otlploghttp.WithHeaders(s.Headers))
	}
	if s.Compression == compressionGzip {
		opts = append(opts, otlploghttp.WithCompression(otlploghttp.GzipCompression))
	} else {
		opts = append(opts, otlploghttp.WithCompression(otlploghttp.NoCompression))
	}
	var tlsCfg *tls.Config
	if !s.Insecure && s.TLS != nil {
		var err error
		if tlsCfg, err = buildTLSConfig(s.TLS); err != nil {
			return nil, err
		}
	}
	if s.guarded {
		// WithHTTPClient takes precedence over WithTLSClientConfig, so the TLS
		// settings are carried by the guarded transport itself.
		opts = append(opts, otlploghttp.WithHTTPClient(guardedHTTPClient(s.Timeout, tlsCfg)))
	} else if tlsCfg != nil {
		opts = append(opts, otlploghttp.WithTLSClientConfig(tlsCfg))
	}
	if s.Insecure {
		opts = append(opts, otlploghttp.WithInsecure())
	}
	return otlploghttp.New(ctx, opts...)
}

// guardedHTTPClient dials only public destinations and carries no proxy, so a
// redirect or an HTTP_PROXY in the environment cannot route around the guard.
func guardedHTTPClient(timeout time.Duration, tlsCfg *tls.Config) *http.Client {
	transport := netguard.NewTransport()
	transport.Proxy = nil
	transport.TLSClientConfig = tlsCfg
	return &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: netguard.CheckRedirect}
}

func guardedGRPCDialer(ctx context.Context, addr string) (net.Conn, error) {
	return netguard.Shared().DialContext(ctx, "tcp", addr)
}

func hasScheme(endpoint string) bool {
	return strings.Contains(endpoint, "://")
}

func buildTLSConfig(t *TLSSettings) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: t.SkipVerify, // #nosec G402 -- operator opt-in via tls.skip_verify for self-signed Collectors
	}
	if t.CAFile != "" {
		pem, err := os.ReadFile(t.CAFile) // #nosec G304 -- path comes from gateway settings already validated by Settings.validate
		if err != nil {
			return nil, fmt.Errorf("otlp: read tls ca file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("otlp: invalid tls ca file %q", t.CAFile)
		}
		cfg.RootCAs = pool
	}
	if t.CertFile != "" || t.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(t.CertFile, t.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("otlp: load tls key pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
	}
	return cfg, nil
}
