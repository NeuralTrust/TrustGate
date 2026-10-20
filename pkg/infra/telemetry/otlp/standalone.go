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
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	sdklog "go.opentelemetry.io/otel/sdk/log"
)

// NewStandaloneLogExporter builds an OTLP log exporter for a pipeline of its
// own. Without an endpoint in override it ships to the operator's collector
// (env, the OTEL_EXPORTER_OTLP_* settings) with the operator's protocol,
// headers and transport; with one, it sends only its own headers, takes its
// own timeout and the protocol from that endpoint, and copies nothing from the
// operator's configuration. TLS material the OTLP SDK reads from the
// OTEL_EXPORTER_OTLP_* environment still applies.
func NewStandaloneLogExporter(ctx context.Context, override, env config.OTLPConfig) (sdklog.Exporter, error) {
	s := standaloneSettings(override, env)
	if err := s.validate(); err != nil {
		return nil, err
	}
	return newLogExporter(ctx, s)
}

func standaloneSettings(override, env config.OTLPConfig) Settings {
	s := Settings{
		Endpoint:    strings.TrimSpace(override.Endpoint),
		Protocol:    Protocol(strings.TrimSpace(override.Protocol)),
		Headers:     override.Headers,
		Timeout:     override.Timeout,
		Insecure:    override.Insecure,
		Compression: override.Compression,
		Signal:      SignalLogs,
	}
	if s.Endpoint == "" {
		s.Endpoint = strings.TrimSpace(env.Endpoint)
		if s.Protocol == "" {
			s.Protocol = Protocol(strings.TrimSpace(env.Protocol))
		}
		if len(s.Headers) == 0 {
			s.Headers = env.Headers
		}
		s.Insecure = s.Insecure || env.Insecure
		if s.Compression == "" {
			s.Compression = env.Compression
		}
		if s.Timeout <= 0 {
			s.Timeout = env.Timeout
		}
	} else {
		s.ownHeaders = true
	}
	if s.Protocol == "" {
		s.Protocol = resolveProtocol(s.Endpoint)
	}
	if s.Timeout <= 0 {
		s.Timeout = defaultTimeout
	}
	if s.Compression == "" {
		s.Compression = defaultCompression
	}
	return s
}
