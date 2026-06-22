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

package gateway

import (
	"fmt"

	appmetrics "github.com/NeuralTrust/TrustGate/pkg/app/metrics"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
)

func validateExporters(factory appmetrics.ExporterFactory, tel *telemetry.Telemetry) error {
	if tel == nil || len(tel.Exporters) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tel.Exporters))
	for _, exporter := range tel.Exporters {
		if _, dup := seen[exporter.Name]; dup {
			return fmt.Errorf("duplicate telemetry exporter %q: %w", exporter.Name, commonerrors.ErrValidation)
		}
		seen[exporter.Name] = struct{}{}
		if factory == nil {
			continue
		}
		if err := factory.Validate(exporter); err != nil {
			return fmt.Errorf("invalid telemetry exporter: %v: %w", err, commonerrors.ErrValidation)
		}
	}
	return nil
}
