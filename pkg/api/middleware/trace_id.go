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

package middleware

import "github.com/google/uuid"

// HeaderTraceID is the response header the proxy sets with the request trace id.
// A gateway-specific name avoids the upstream X-Request-Id some providers emit.
const HeaderTraceID = "X-AG-Trace-Id"

// newTraceID mints the identity of a gateway request. An inbound HeaderTraceID
// is never reused: the trace id keys telemetry storage, so honouring a
// caller-supplied value lets any client silently drop another request's row,
// including one belonging to a different tenant (RUN-1138).
func newTraceID() string {
	return uuid.New().String()
}

// StrippedProxyResponseHeaders lists upstream headers that must not be forwarded to clients.
var StrippedProxyResponseHeaders = map[string]struct{}{
	"X-Request-Id": {},
}
