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

package plugins

import "encoding/json"

// A2ABody is the body the A2A plane hands its policies in place of the
// JSON-RPC call: the same for every protocol version, with the parts the
// call or its answer carries.
type A2ABody struct {
	Method string    `json:"method,omitempty"`
	Agent  string    `json:"agent,omitempty"`
	Parts  []A2APart `json:"parts"`
}

// A2APart is a message or artifact part of an A2ABody.
type A2APart struct {
	Type      string          `json:"type"`
	Text      string          `json:"text,omitempty"`
	Data      json.RawMessage `json:"data,omitempty"`
	URL       string          `json:"url,omitempty"`
	Raw       string          `json:"raw,omitempty"`
	MediaType string          `json:"media_type,omitempty"`
	Filename  string          `json:"filename,omitempty"`
}

// A2APart types.
const (
	A2APartText = "text"
	A2APartData = "data"
	A2APartFile = "file"
)
