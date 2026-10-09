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

package context

import (
	"time"
)

type ResponseContext struct {
	GatewayID  string
	RegistryID string
	Headers    map[string][]string
	Body       []byte
	StatusCode int
	Streaming  bool
	// StreamCut is set by the proxy, and only there, when a stream guard cut
	// the response mid-stream: what was delivered ends on the cut terminator
	// and nothing after the cut reached the client. It is read at
	// post_response so a plugin does not re-inspect, and report on, a body
	// that was already blocked. Nothing derived from the request or the
	// upstream response can set it.
	StreamCut bool
	// StreamFinalInspected is set by the proxy, and only there, when the stream
	// guard evaluated the stream's final block in full: every entry answered and
	// the call carried the whole accumulated text, not a tail window. The
	// post_response pass over the drained body would read the same text again, so
	// a plugin whose own policy entry opted into per-block inspection skips it.
	// Nothing derived from the request or the upstream response can set it.
	StreamFinalInspected bool
	TargetLatency        float64
	ProcessAt            *time.Time
	// Metadata carries values plugins pass across stages within a single
	// request (e.g. cache status on PreRequest read back on PostResponse).
	Metadata map[string]interface{}
}
