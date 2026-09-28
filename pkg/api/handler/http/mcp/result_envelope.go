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

package mcp

import (
	"encoding/json"
	"strconv"

	"github.com/gofiber/fiber/v2"
)

// The 2026-07-28 result envelope.
//
// Under that revision every result says what kind of result it is, and the
// ones a client may cache also say for how long and whose copy it is. The
// gateway stamps them on every answer whatever revision it negotiated: a
// result has allowed unknown fields in every revision, so one answer shape
// serves an old client and a new one, and there is no second code path to
// keep honest.
const (
	// resultTypeComplete: this answer is finished. The other value the revision
	// defines, input_required, belongs to a server that is still asking the
	// user something — which this gateway never is on its own, but an upstream
	// may be, so a relayed result that already says so keeps what it said.
	resultTypeComplete = "complete"

	// cacheScopePrivate: every answer here is computed for one principal — the
	// servers they installed, the accounts they signed in, the policy their
	// groups carry. No intermediary may serve one caller's copy to another.
	cacheScopePrivate = "private"

	// surfaceCacheTTLMs is zero because a surface changes the moment a user
	// installs a server or signs an account in. A client holding a copy from
	// before that is the whole reason a freshly installed server does not turn
	// up in the tool list.
	surfaceCacheTTLMs = 0
)

// cacheHintMethods are the results the revision lets a client cache — the ones
// whose type extends CacheableResult. A tool call is not among them: its result
// is an effect, not a description of the server.
var cacheHintMethods = map[string]struct{}{
	"tools/list":               {},
	"resources/list":           {},
	"resources/templates/list": {},
	"resources/read":           {},
	"prompts/list":             {},
}

// stampResultEnvelope puts the envelope on the result the gateway is about to
// answer with, whether it composed that result or relayed it from an upstream.
//
// The relayed ones are why this exists. They come from servers speaking an
// older revision, so nothing in them carries resultType; a gateway that
// advertises 2026-07-28 and forwards one verbatim hands its client a result the
// client is entitled to reject. Stamping happens here, once, on the way out,
// rather than in each of the handlers that can produce one.
func stampResultEnvelope(method string, result any) any {
	switch typed := result.(type) {
	case json.RawMessage:
		return stampRawResult(method, typed)
	case fiber.Map:
		stampResultMap(method, typed)
		return typed
	case map[string]any:
		stampResultMap(method, typed)
		return typed
	default:
		// A Go value the gateway built (an empty ping result, say). Encoding it
		// here costs one marshal and keeps every answer on one path.
		raw, err := json.Marshal(result)
		if err != nil {
			return result
		}
		return stampRawResult(method, raw)
	}
}

func stampResultMap(method string, fields map[string]any) {
	if _, ok := fields["resultType"]; !ok {
		fields["resultType"] = resultTypeComplete
	}
	if _, cacheable := cacheHintMethods[method]; !cacheable {
		return
	}
	fields["ttlMs"] = surfaceCacheTTLMs
	fields["cacheScope"] = cacheScopePrivate
}

// stampRawResult rewrites only the top level of an encoded result: every value
// under it is carried across as the bytes that arrived, so relaying stays
// lossless.
//
// The cache hints are set rather than defaulted. An upstream describes its own
// answer, and this gateway's answer is not that one: it is built for a single
// principal out of their credentials and their policy, so an upstream that
// called its result public would be wrong about the copy being served here, and
// one that called it long-lived would be wrong about how long it holds.
func stampRawResult(method string, raw json.RawMessage) json.RawMessage {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		// Not a JSON object. Nothing the gateway emits looks like this, and an
		// upstream that answered with something else is relayed as it was
		// rather than rewritten on a guess.
		return raw
	}
	if _, ok := fields["resultType"]; !ok {
		fields["resultType"] = json.RawMessage(`"` + resultTypeComplete + `"`)
	}
	if _, cacheable := cacheHintMethods[method]; cacheable {
		fields["ttlMs"] = json.RawMessage(strconv.Itoa(surfaceCacheTTLMs))
		fields["cacheScope"] = json.RawMessage(`"` + cacheScopePrivate + `"`)
	}
	out, err := json.Marshal(fields)
	if err != nil {
		return raw
	}
	return out
}
