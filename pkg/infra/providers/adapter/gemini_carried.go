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
	"errors"
	"maps"
	"slices"
	"strings"
	"unicode"
)

// geminiCarriedKeys are the top-level Gemini keys a re-encode carries through
// RequestExtensions, as responsesCarriedKeys are for Responses. They hold no
// prompt text, and dropping them changes how the upstream answers: without
// safetySettings a masked request falls back to Google's default thresholds,
// and without cachedContent it loses the cached context (ENG-3682). labels,
// which may hold personal data, is left out, and so are tools and toolConfig:
// tool_allowlist re-encodes a request to drop what it refuses.
var geminiCarriedKeys = []string{"safetySettings", "cachedContent"}

// geminiCarriedGenConfigKeys are the generationConfig keys the canonical model
// does not carry and a re-encode keeps, under the same rule. speechConfig,
// which may name the speakers, is left out. A responseMimeType other than
// application/json, which the canonical model cannot express, is kept too.
var geminiCarriedGenConfigKeys = []string{
	"stopSequences", "candidateCount", "seed", "presencePenalty", "frequencyPenalty",
	"responseLogprobs", "logprobs", "responseSchema", "responseJsonSchema",
	"responseModalities", "mediaResolution", "thinkingConfig", "imageConfig",
}

const (
	geminiGenConfigExtension = "generationConfig"
	geminiJSONMimeType       = "application/json"
	geminiResponseMimeType   = "responseMimeType"
)

// carryRaw sets dst[key] to the first of values the client set to something
// other than null.
func carryRaw(dst map[string]json.RawMessage, key string, values ...json.RawMessage) map[string]json.RawMessage {
	for _, v := range values {
		if isEmptyOrNull(v) {
			continue
		}
		if dst == nil {
			dst = map[string]json.RawMessage{}
		}
		dst[key] = v
		return dst
	}
	return dst
}

// carriedGenConfig reads the geminiCarriedGenConfigKeys of a generationConfig
// object, the camelCase spelling winning over the snake_case one.
func carriedGenConfig(b []byte, mimeType string) (map[string]json.RawMessage, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	var carried map[string]json.RawMessage
	for _, key := range geminiCarriedGenConfigKeys {
		carried = carryRaw(carried, key, raw[key], raw[snakeCase(key)])
	}
	if mimeType != "" && mimeType != geminiJSONMimeType {
		v, err := json.Marshal(mimeType)
		if err != nil {
			return nil, err
		}
		carried = carryRaw(carried, geminiResponseMimeType, v)
	}
	return carried, nil
}

func snakeCase(camel string) string {
	var b strings.Builder
	for _, r := range camel {
		if unicode.IsUpper(r) {
			b.WriteByte('_')
			r = unicode.ToLower(r)
		}
		b.WriteRune(r)
	}
	return b.String()
}

func geminiRequestExtensions(req *geminiRequest) map[string]json.RawMessage {
	ext := maps.Clone(req.carried)
	if gc := req.GenerationConfig; gc != nil && len(gc.carried) > 0 {
		if b, err := json.Marshal(gc.carried); err == nil {
			ext = carryRaw(ext, geminiGenConfigExtension, b)
		}
	}
	return ext
}

// geminiCarriedFrom returns the values req carries for keys. Only those keys
// are read, so an extension another format's decoder recorded never reaches a
// Gemini body.
func geminiCarriedFrom(ext map[string]json.RawMessage, keys []string) map[string]json.RawMessage {
	var out map[string]json.RawMessage
	for _, key := range keys {
		if v, ok := ext[key]; ok && json.Valid(v) {
			out = carryRaw(out, key, v)
		}
	}
	return out
}

func geminiCarriedGenConfigFrom(ext map[string]json.RawMessage) map[string]json.RawMessage {
	var raw map[string]json.RawMessage
	if json.Unmarshal(ext[geminiGenConfigExtension], &raw) != nil {
		return nil
	}
	return geminiCarriedFrom(raw, append(slices.Clip(geminiCarriedGenConfigKeys), geminiResponseMimeType))
}

// appendRawFields adds fields, in key order, to the end of the JSON object obj.
func appendRawFields(obj []byte, fields map[string]json.RawMessage) ([]byte, error) {
	if len(fields) == 0 {
		return obj, nil
	}
	end := bytes.LastIndexByte(obj, '}')
	if end < 0 {
		return nil, errors.New("gemini: encoded request is not a JSON object")
	}
	out := bytes.NewBuffer(make([]byte, 0, len(obj)+64))
	out.Write(obj[:end])
	empty := len(bytes.TrimSpace(obj[1:end])) == 0
	for _, key := range slices.Sorted(maps.Keys(fields)) {
		if !empty {
			out.WriteByte(',')
		}
		empty = false
		k, err := json.Marshal(key)
		if err != nil {
			return nil, err
		}
		out.Write(k)
		out.WriteByte(':')
		if err := json.Compact(out, fields[key]); err != nil {
			return nil, err
		}
	}
	out.Write(obj[end:])
	return out.Bytes(), nil
}
