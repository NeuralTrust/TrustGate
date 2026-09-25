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
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
)

// LegacyFunctionKind is the UnmodelledTool kind of an entry of Chat's legacy
// functions list.
const LegacyFunctionKind = "functions"

// LegacyFunctionCall is a call made through Chat's legacy function API: an
// assistant message with a function_call, answered by a function message.
// The canonical request models neither.
type LegacyFunctionCall struct {
	// ID stands in for the call id the legacy API does not have. It is
	// derived from the call's position, name and arguments, so the same
	// call replayed in a later request of the conversation keeps it.
	ID   string
	Name string
}

type legacyChatMessages struct {
	Messages []struct {
		Role         string `json:"role"`
		Name         string `json:"name"`
		FunctionCall *struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function_call"`
	} `json:"messages"`
}

// ExecutedLegacyFunctionCalls returns the legacy function calls of the
// latest assistant turn that made one and that a later function message of
// the same name answers. It is empty for formats without the legacy API or
// a body that does not decode.
func ExecutedLegacyFunctionCalls(ad RequestAdapter, body []byte) []LegacyFunctionCall {
	if extraToolList(ad) != LegacyFunctionKind {
		return nil
	}
	var in legacyChatMessages
	if json.Unmarshal(body, &in) != nil {
		return nil
	}
	turn := -1
	for i, m := range in.Messages {
		if m.Role == "assistant" && m.FunctionCall != nil && m.FunctionCall.Name != "" {
			turn = i
		}
	}
	if turn < 0 {
		return nil
	}
	call := in.Messages[turn].FunctionCall
	for _, m := range in.Messages[turn+1:] {
		if m.Role == "function" && m.Name == call.Name {
			sum := sha256.Sum256([]byte(strconv.Itoa(turn) + "\x00" + call.Name + "\x00" + call.Arguments))
			return []LegacyFunctionCall{{ID: "function_call:" + hex.EncodeToString(sum[:12]), Name: call.Name}}
		}
	}
	return nil
}
