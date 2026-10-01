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

package prompttemplate

const (
	decisionInjected = "injected"
	decisionRendered = "rendered"
	decisionObserved = "observed"
	decisionNoOp     = "no_op"
	decisionSkipped  = "skipped"
	// decisionSkippedFormat marks a request whose wire format the plugin does
	// not model, and decisionSkippedShape one whose body is shaped in a way it
	// cannot edit safely. Both leave the body untouched.
	decisionSkippedFormat = "skipped_unsupported_format"
	decisionSkippedShape  = "skipped_unsupported_shape"
)

// unappliedInjection records a Mode A template that was rendered but never
// reached the request, with the reason, so the event does not report a
// success the model never saw.
type unappliedInjection struct {
	ID     string `json:"id"`
	Reason string `json:"reason"`
}

type PromptTemplateData struct {
	Decision         string   `json:"decision"`
	InjectedIDs      []string `json:"injected_ids,omitempty"`
	SkippedIDs       []string `json:"skipped_ids,omitempty"`
	UnresolvedIDs    []string `json:"unresolved_variables,omitempty"`
	ResolvedTemplate string   `json:"resolved_template,omitempty"`
	// DiscardedMessages counts the conversation turns a rendered template
	// replaced, which is otherwise invisible to the caller and to the operator.
	DiscardedMessages int `json:"discarded_messages,omitempty"`
	// DroppedClientVariables names client-supplied variables that collided
	// with a gateway-resolved context variable (from a JWT claim or a
	// trusted header) and were dropped in its favour, which is otherwise
	// invisible to the caller and to the operator.
	DroppedClientVariables []string `json:"dropped_client_variables,omitempty"`
	// Unapplied lists Mode A templates that could not be placed in the
	// request. skipped_ids is a different thing: a missing context variable.
	Unapplied []unappliedInjection `json:"unapplied,omitempty"`
	// SkippedReason names why the whole request was passed through untouched:
	// the wire format or the body shape.
	SkippedReason string `json:"skipped_reason,omitempty"`
	// UnscannedTemplateReference is true when a request passed through
	// untouched still carries a {template://...} token the plugin never
	// scanned, so the literal reaches the model.
	UnscannedTemplateReference bool `json:"unscanned_template_reference,omitempty"`
}
