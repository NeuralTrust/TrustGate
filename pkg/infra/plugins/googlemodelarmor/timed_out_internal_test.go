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

package googlemodelarmor

import (
	"context"
	"errors"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
)

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "Client.Timeout exceeded while awaiting headers" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

// http.Client.Timeout can end the call a moment before the context passes its
// deadline: the call is still a timeout, so timeout_failure_mode decides it,
// not failure_mode (a race that made "allow outages, block slow" release slow
// blocks now and then).
func TestTimedOutReadsTheClientTimeout(t *testing.T) {
	t.Parallel()
	clientTimeout := &url.Error{Op: "Post", URL: "http://x", Err: timeoutErr{}}

	_, detail := failureOfError(timedOut(context.Background(), clientTimeout))
	assert.Equal(t, appplugins.DetailTimeout, detail, "the client's own timeout is a timeout")

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	_, detail = failureOfError(timedOut(canceled, clientTimeout))
	assert.Empty(t, detail, "a cancelled call is never a timeout")

	_, detail = failureOfError(timedOut(context.Background(), errors.New("503")))
	assert.Empty(t, detail, "an outage is not a timeout")
}
