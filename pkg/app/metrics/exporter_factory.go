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

package metrics

import telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"

//go:generate mockery --name=ExporterFactory --dir=. --output=./mocks --filename=exporter_factory_mock.go --case=underscore --with-expecter
type ExporterFactory interface {
	// Build and Validate serve configuration the operator wrote: the defaults
	// file or TELEMETRY_EXPORTERS_* variables.
	Build(cfg telemetrydomain.ExporterConfig) (Exporter, error)
	Validate(cfg telemetrydomain.ExporterConfig) error
	// BuildTenant and ValidateTenant serve configuration a tenant wrote into a
	// gateway. Its destinations, credentials and file paths are untrusted, so an
	// exporter may refuse settings the operator is allowed to use (an
	// operator-owned env var as a DSN, files on the pod) and must reach only
	// public addresses unless the operator opted into private networks.
	BuildTenant(cfg telemetrydomain.ExporterConfig) (Exporter, error)
	ValidateTenant(cfg telemetrydomain.ExporterConfig) error
}
