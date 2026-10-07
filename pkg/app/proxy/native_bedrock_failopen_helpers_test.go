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

package proxy_test

import (
	"context"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// tracedContext is a context whose request trace the test can read back.
func tracedContext() (context.Context, *trace.RequestTrace) {
	rt := trace.New("native-mask-trace", trace.Metadata{})
	return trace.NewContext(context.Background(), rt), rt
}

// failedOpenEntries are the policy-chain entries recorded as failed open for a
// mask that could not be applied: what the console shows in Activity.
func failedOpenEntries(rt *trace.RequestTrace) []*appplugins.NativeMaskData {
	var out []*appplugins.NativeMaskData
	for _, span := range rt.Spans() {
		if span.Type != trace.SpanPlugin || span.Name != appplugins.BedrockNativePassthrough {
			continue
		}
		attrs := span.PluginAttrsCopy()
		if data, ok := attrs.Extras.(*appplugins.NativeMaskData); ok && attrs.Decision == appplugins.DecisionFailedOpen {
			out = append(out, data)
		}
	}
	return out
}

// requireFailedOpen asserts one failed-open entry, with this stage and a failure
// reason that starts with mask_not_applicable: and ends with cause.
func requireFailedOpen(t *testing.T, rt *trace.RequestTrace, stage, cause string) {
	t.Helper()
	entries := failedOpenEntries(rt)
	require.Len(t, entries, 1, "one failed-open entry per kind of cause")
	assert.Equal(t, appplugins.DecisionFailedOpen, entries[0].Decision)
	assert.Equal(t, stage, entries[0].Stage)
	assert.Equal(t, "mask_not_applicable:"+cause, entries[0].FailureReason)
}
