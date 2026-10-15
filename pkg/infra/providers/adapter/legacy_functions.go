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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// LegacyFunctionKind is the UnmodelledTool kind of an entry of Chat's legacy
// functions list.
const LegacyFunctionKind = "functions"

// LegacyFunctionCall is a call made through Chat's legacy function API: an
// assistant message with a function_call, answered by a function message.
// The canonical request models neither.
type LegacyFunctionCall struct {
	// ID stands in for the call id the legacy API does not have. It is a
	// digest of the messages up to and including the call, its name and its
	// arguments, so the same call replayed in a later request of the
	// conversation keeps it, while the same call in another conversation,
	// or in a history the client trimmed, gets another.
	ID   string
	Name string
}

type legacyChatMessage struct {
	Role         string `json:"role"`
	Name         string `json:"name"`
	FunctionCall *struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function_call"`
}

// ExecutedLegacyFunctionCalls returns the legacy function calls of the
// latest assistant turn that made one and that a later function message of
// the same name answers. Messages that do not decode are skipped. It is
// empty for formats without the legacy API or a body without a messages
// list.
func ExecutedLegacyFunctionCalls(ad RequestAdapter, body []byte) []LegacyFunctionCall {
	if extraToolList(ad) != LegacyFunctionKind {
		return nil
	}
	var in struct {
		Messages []json.RawMessage `json:"messages"`
	}
	if json.Unmarshal(body, &in) != nil {
		return nil
	}
	msgs := make([]legacyChatMessage, len(in.Messages))
	turn := -1
	for i, raw := range in.Messages {
		if json.Unmarshal(raw, &msgs[i]) != nil {
			msgs[i] = legacyChatMessage{}
			continue
		}
		if m := msgs[i]; m.Role == "assistant" && m.FunctionCall != nil && m.FunctionCall.Name != "" {
			turn = i
		}
	}
	if turn < 0 {
		return nil
	}
	call := msgs[turn].FunctionCall
	for _, m := range msgs[turn+1:] {
		if m.Role == "function" && m.Name == call.Name {
			return []LegacyFunctionCall{{ID: legacyCallID(in.Messages[:turn+1], call.Name, call.Arguments), Name: call.Name}}
		}
	}
	return nil
}

func legacyCallID(prefix []json.RawMessage, name, arguments string) string {
	h := sha256.New()
	var compact bytes.Buffer
	for _, raw := range prefix {
		compact.Reset()
		if json.Compact(&compact, raw) != nil {
			compact.Write(raw)
		}
		h.Write(compact.Bytes())
		h.Write([]byte{0})
	}
	h.Write([]byte(name))
	h.Write([]byte{0})
	h.Write([]byte(arguments))
	return "function_call:" + hex.EncodeToString(h.Sum(nil)[:12])
}
