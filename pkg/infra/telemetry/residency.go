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

package telemetry

import (
	"errors"
	"fmt"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	metricsschema "github.com/NeuralTrust/TrustGate/pkg/metrics"
)

// RemoteRawExporterType is the exporter type that hands raw payloads to a
// collector over the network. It repeats otlp.ExporterName as a literal because
// the otlp package imports this one.
const RemoteRawExporterType = "otlp"

// ErrRawResidency reports a raw exporter that would carry request and response
// bodies out of the customer boundary.
var ErrRawResidency = errors.New("raw telemetry would leave the customer boundary")

// CheckRawResidency rejects raw-class exporters that ship payloads off-box while
// the process runs as a hybrid data plane, so the guarantee holds on every
// deployment shape rather than only under the Helm chart (RUN-1237). The
// gateway cannot see past the collector hop, so the exporter type is the signal:
// allowRemote is the operator's explicit opt-in, mirroring the chart's
// global.telemetry.rawRemoteExperimental.
func CheckRawResidency(configs []telemetrydomain.ExporterConfig, hybrid, allowRemote bool) error {
	if !hybrid || allowRemote {
		return nil
	}
	for _, cfg := range configs {
		if cfg.Class != metricsschema.Raw || cfg.EffectiveType() != RemoteRawExporterType {
			continue
		}
		return fmt.Errorf(
			"%w: raw exporter %q has type %q on a hybrid data plane; keep raw payloads on-box (postgres) "+
				"or set TELEMETRY_RAW_REMOTE_EXPERIMENTAL=true to override",
			ErrRawResidency, cfg.Name, cfg.EffectiveType(),
		)
	}
	return nil
}
