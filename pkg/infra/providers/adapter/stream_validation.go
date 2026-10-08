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

package adapter

import (
	"bytes"
	"encoding/json"
)

func streamJSONFields(raw []byte) (map[string]json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		return nil, false
	}
	return fields, true
}

func streamJSONObject(fields map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool) {
	raw, exists := fields[key]
	if !exists {
		return nil, true
	}
	return streamJSONFields(raw)
}

func streamNullableJSONObject(fields map[string]json.RawMessage, key string) (map[string]json.RawMessage, bool) {
	if bytes.Equal(bytes.TrimSpace(fields[key]), []byte("null")) {
		return nil, true
	}
	return streamJSONObject(fields, key)
}

func streamJSONArray(fields map[string]json.RawMessage, key string) ([]json.RawMessage, bool) {
	raw, exists := fields[key]
	if !exists {
		return nil, true
	}
	var items []json.RawMessage
	if json.Unmarshal(raw, &items) != nil || items == nil {
		return nil, false
	}
	return items, true
}

func streamFieldsNonNull(fields map[string]json.RawMessage, keys ...string) bool {
	for _, key := range keys {
		if raw, exists := fields[key]; exists && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
			return false
		}
	}
	return true
}

// InvalidStreamEventType is the type used for decoder-generated unreadable upstream events.
const InvalidStreamEventType = "invalid_stream_event"

func invalidStreamEvent(provider string) *CanonicalStreamChunk {
	return &CanonicalStreamChunk{UpstreamError: &UpstreamStreamError{
		Type: InvalidStreamEventType, Message: "invalid upstream " + provider + " stream event", decoderFailure: true,
	}}
}

func failedStreamEvent(provider string) *CanonicalStreamChunk {
	return &CanonicalStreamChunk{UpstreamError: &UpstreamStreamError{
		Type: "upstream_error", Message: "upstream " + provider + " stream failed",
	}}
}
