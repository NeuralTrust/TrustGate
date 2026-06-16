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

// SSEEvent builds the standard SSE lines for one event:
//
//	event: <eventType>
//	data: <dataJSON>
//	<empty line>
//
// The caller writes each element followed by "\n".
func SSEEvent(eventType string, dataJSON []byte) [][]byte {
	return [][]byte{
		[]byte("event: " + eventType),
		append([]byte("data: "), dataJSON...),
		{}, // empty-line separator
	}
}

// SSEData builds a single "data: …" line followed by an empty separator.
// This is the format used by providers that do not emit "event:" lines
// (e.g. OpenAI, Azure).
func SSEData(dataJSON []byte) [][]byte {
	return [][]byte{
		append([]byte("data: "), dataJSON...),
		{}, // empty-line separator
	}
}
