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

package telemetry_test

import (
	"testing"

	telemetrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/telemetry"
	"github.com/stretchr/testify/assert"
)

func TestExporterConfig_EffectiveType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  telemetrydomain.ExporterConfig
		want string
	}{
		{
			name: "type set returns type",
			cfg:  telemetrydomain.ExporterConfig{Name: "a", Type: "otlp"},
			want: "otlp",
		},
		{
			name: "type empty returns name",
			cfg:  telemetrydomain.ExporterConfig{Name: "kafka"},
			want: "kafka",
		},
		{
			name: "both empty returns empty",
			cfg:  telemetrydomain.ExporterConfig{},
			want: "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tt.want, tt.cfg.EffectiveType())
		})
	}
}
