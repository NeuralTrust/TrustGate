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

package events_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics/events"
	"github.com/stretchr/testify/assert"
)

func TestRedactHeaders_RedactsSensitiveHeaders(t *testing.T) {
	headers := map[string][]string{
		"Authorization":         {"Bearer secret"},
		"X-AG-Api-Key":          {"super-secret-key"},
		"X-AG-Playground-Token": {"eyJhbGciOiJIUzI1NiJ9.playground.jwt"},
		"Content-Type":          {"application/json"},
	}

	out := events.RedactHeaders(headers)

	assert.Equal(t, []string{"[REDACTED]"}, out["Authorization"])
	assert.Equal(t, []string{"[REDACTED]"}, out["X-AG-Api-Key"])
	assert.Equal(t, []string{"[REDACTED]"}, out["X-AG-Playground-Token"],
		"playground token must never reach a telemetry exporter or the trace store")
	assert.Equal(t, []string{"application/json"}, out["Content-Type"])
}

func TestRedactHeaders_NilReturnsNil(t *testing.T) {
	assert.Nil(t, events.RedactHeaders(nil))
}
