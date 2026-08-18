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
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/mitchellh/mapstructure"
)

// ExporterName is the registered name of the OTLP exporter template.
const ExporterName = "otlp"

// Protocol selects the OTLP transport used to reach the Collector.
type Protocol string

// Signal selects the OTel signal the exporter emits. Only SignalLogs is
// implemented; SignalTraces is reserved for a future spans exporter.
type Signal string

const (
	ProtocolGRPC Protocol = "grpc"
	ProtocolHTTP Protocol = "http/protobuf"

	SignalLogs   Signal = "logs"
	SignalTraces Signal = "traces"

	compressionGzip = "gzip"
	compressionNone = "none"

	defaultProtocol     = ProtocolGRPC
	defaultSignal       = SignalLogs
	defaultCompression  = compressionGzip
	defaultTimeout      = 10 * time.Second
	// Kept above events.MaxSanitizedBodyBytes on purpose: the sanitizer is the
	// only component allowed to truncate a body, because it marks the cut. When
	// this limit is the smaller of the two the SDK silently slices attributes
	// mid-JSON, which drops the trailing usage chunk of streamed responses.
	defaultMaxBodyBytes = 2 * 1024 * 1024

	otlpGRPCPort = "4317"
	otlpHTTPPort = "4318"
)

// TLSSettings configures mutual or server-only TLS for the OTLP transport.
type TLSSettings struct {
	CAFile     string `mapstructure:"ca_file"`
	CertFile   string `mapstructure:"cert_file"`
	KeyFile    string `mapstructure:"key_file"`
	SkipVerify bool   `mapstructure:"skip_verify"`
}

// Settings is the per-gateway configuration for the OTLP exporter, decoded from
// the gateway's telemetry exporter Settings map and merged with process-level
// OTEL_EXPORTER_OTLP_* defaults.
type Settings struct {
	Endpoint     string            `mapstructure:"endpoint"`
	Protocol     Protocol          `mapstructure:"protocol"`
	Signal       Signal            `mapstructure:"signal"`
	Headers      map[string]string `mapstructure:"headers"`
	Insecure     bool              `mapstructure:"insecure"`
	TLS          *TLSSettings      `mapstructure:"tls"`
	Timeout      time.Duration     `mapstructure:"timeout"`
	Compression  string            `mapstructure:"compression"`
	MaxBodyBytes int               `mapstructure:"max_body_bytes"`
}

// parseSettings decodes raw gateway settings, applies the env fallback
// (settings win over env), then fills defaults. Unknown keys are ignored.
func parseSettings(raw map[string]interface{}, env config.OTLPConfig) (Settings, error) {
	var s Settings
	if len(raw) > 0 {
		decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{
			DecodeHook: mapstructure.StringToTimeDurationHookFunc(),
			Result:     &s,
		})
		if err != nil {
			return Settings{}, fmt.Errorf("otlp: %w", err)
		}
		if err := decoder.Decode(raw); err != nil {
			return Settings{}, fmt.Errorf("otlp: invalid settings: %w", err)
		}
	}

	if s.Endpoint == "" {
		s.Endpoint = strings.TrimSpace(env.Endpoint)
	}
	if s.Protocol == "" && env.Protocol != "" {
		s.Protocol = Protocol(env.Protocol)
	}
	if len(s.Headers) == 0 && len(env.Headers) > 0 {
		s.Headers = env.Headers
	}
	if s.Timeout == 0 {
		s.Timeout = env.Timeout
	}
	if _, ok := raw["insecure"]; !ok {
		s.Insecure = env.Insecure
	}
	if s.Compression == "" && env.Compression != "" {
		s.Compression = env.Compression
	}

	if s.Protocol == "" {
		s.Protocol = resolveProtocol(s.Endpoint)
	}
	if s.Signal == "" {
		s.Signal = defaultSignal
	}
	if s.Timeout == 0 {
		s.Timeout = defaultTimeout
	}
	if s.Compression == "" {
		s.Compression = defaultCompression
	}
	if s.MaxBodyBytes <= 0 {
		s.MaxBodyBytes = defaultMaxBodyBytes
	}
	return s, nil
}

// resolveProtocol picks the wire protocol for exporters that declare none, either
// in their settings or through OTEL_EXPORTER_OTLP_PROTOCOL: a gRPC client aimed at
// an OTLP/HTTP collector fails on every export rather than at boot. A path
// (/v1/logs) or port 4318 only exist on the HTTP form; gRPC endpoints are
// host:4317.
func resolveProtocol(endpoint string) Protocol {
	host, path := splitEndpoint(endpoint)
	if strings.Trim(path, "/") != "" {
		return ProtocolHTTP
	}
	switch portOf(host) {
	case otlpHTTPPort:
		return ProtocolHTTP
	case otlpGRPCPort:
		return ProtocolGRPC
	}
	return defaultProtocol
}

// splitEndpoint separates the authority from the path of an OTLP endpoint, which
// may be a full URL or a bare host:port.
func splitEndpoint(endpoint string) (host, path string) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return "", ""
	}
	if !hasScheme(endpoint) {
		endpoint = "//" + endpoint
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return endpoint, ""
	}
	return u.Host, u.Path
}

// portOf returns the port of an authority, or an empty string when it carries none.
func portOf(host string) string {
	_, port, err := net.SplitHostPort(host)
	if err != nil {
		return ""
	}
	return port
}

// validate performs structural validation only; it never performs network I/O.
func (s Settings) validate() error {
	if strings.TrimSpace(s.Endpoint) == "" {
		return errors.New("otlp: endpoint is required (set settings.endpoint or OTEL_EXPORTER_OTLP_ENDPOINT)")
	}
	switch s.Protocol {
	case ProtocolGRPC, ProtocolHTTP:
	default:
		return fmt.Errorf("otlp: invalid protocol %q (want %q or %q)", s.Protocol, ProtocolGRPC, ProtocolHTTP)
	}
	if s.Protocol == ProtocolGRPC {
		if _, path := splitEndpoint(s.Endpoint); strings.Trim(path, "/") != "" {
			return fmt.Errorf(
				"otlp: grpc endpoint %q must not carry a path; drop it or set protocol %q",
				s.Endpoint, ProtocolHTTP,
			)
		}
	}
	switch s.Signal {
	case SignalLogs:
	case SignalTraces:
		return fmt.Errorf("otlp: signal %q is reserved but not implemented; use %q", SignalTraces, SignalLogs)
	default:
		return fmt.Errorf("otlp: invalid signal %q (want %q or %q)", s.Signal, SignalLogs, SignalTraces)
	}
	if s.Timeout <= 0 {
		return fmt.Errorf("otlp: timeout must be greater than zero, got %s", s.Timeout)
	}
	if s.Compression != compressionGzip && s.Compression != compressionNone {
		return fmt.Errorf("otlp: invalid compression %q (want %q or %q)", s.Compression, compressionGzip, compressionNone)
	}
	if s.Insecure && s.TLS != nil {
		return errors.New("otlp: insecure cannot be combined with tls settings")
	}
	if s.TLS != nil {
		if (s.TLS.CertFile == "") != (s.TLS.KeyFile == "") {
			return errors.New("otlp: tls cert_file and key_file must be provided together")
		}
		for _, file := range []string{s.TLS.CAFile, s.TLS.CertFile, s.TLS.KeyFile} {
			if file == "" {
				continue
			}
			if _, err := os.Stat(file); err != nil {
				return fmt.Errorf("otlp: tls file %q: %w", file, err)
			}
		}
	}
	return nil
}
