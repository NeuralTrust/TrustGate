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

// Package bedrocknative holds what the request context and the adapter share about
// a native Amazon Bedrock Runtime call: the operations it can name.
package bedrocknative

// Op is the Bedrock Runtime operation a native request calls.
type Op string

const (
	Converse       Op = "converse"
	ConverseStream Op = "converse-stream"
	Invoke         Op = "invoke"
	InvokeStream   Op = "invoke-with-response-stream"
)

// IsStream reports whether the operation answers with an event stream.
func (op Op) IsStream() bool { return op == ConverseStream || op == InvokeStream }

// IsConverse reports whether the operation speaks the Converse schema, as opposed
// to the model-native InvokeModel one.
func (op Op) IsConverse() bool { return op == Converse || op == ConverseStream }

// Valid reports one of the four operations.
func (op Op) Valid() bool {
	switch op {
	case Converse, ConverseStream, Invoke, InvokeStream:
		return true
	default:
		return false
	}
}
