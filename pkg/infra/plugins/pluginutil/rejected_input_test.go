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

package pluginutil_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
)

type rejection struct {
	status       int
	configShaped bool
}

func (r *rejection) Error() string          { return fmt.Sprintf("status %d", r.status) }
func (r *rejection) Rejection() (int, bool) { return r.status, r.configShaped }

func TestFailureOfError(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name   string
		err    error
		reason appplugins.FailureReason
		detail string
	}{
		{"a 400 about the content", &rejection{status: http.StatusBadRequest}, appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput},
		{"a 400 about the configuration", &rejection{status: http.StatusBadRequest, configShaped: true}, appplugins.FailureConfigInvalid, appplugins.DetailProviderConfigRejected},
		{"a 413", &rejection{status: http.StatusRequestEntityTooLarge}, appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput},
		{"a 401", &rejection{status: http.StatusUnauthorized}, appplugins.FailureTransport, ""},
		{"a 429", &rejection{status: http.StatusTooManyRequests}, appplugins.FailureTransport, ""},
		{"a 503", &rejection{status: http.StatusServiceUnavailable}, appplugins.FailureTransport, ""},
		{"a wrapped rejection", fmt.Errorf("call: %w", &rejection{status: http.StatusBadRequest}), appplugins.FailureInputTooLarge, appplugins.DetailProviderRejectedInput},
		{"a deadline", context.DeadlineExceeded, appplugins.FailureTransport, ""},
		{"a network error", errors.New("dial tcp: refused"), appplugins.FailureTransport, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reason, detail := pluginutil.FailureOfError(tc.err)
			assert.Equal(t, tc.reason, reason)
			assert.Equal(t, tc.detail, detail)
		})
	}
}
