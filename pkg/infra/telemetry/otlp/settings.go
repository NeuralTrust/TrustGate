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
	"os"
	"strings"
	"time"

	"github.com/NeuralTrust/AgentGateway/pkg/config"
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
	defaultMaxBodyBytes = 4096
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
		s.Protocol = defaultProtocol
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
