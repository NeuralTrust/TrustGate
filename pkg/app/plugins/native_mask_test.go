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

package plugins_test

import (
	"bytes"
	"context"
	"log/slog"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecordNativeMaskBlocked_IsABlockedPolicyEntryWithTheCause(t *testing.T) {
	t.Parallel()
	rt := trace.New("t", trace.Metadata{})
	var logs bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logs, nil))

	appplugins.RecordNativeMaskBlocked(trace.NewContext(context.Background(), rt), logger, policy.StagePreRequest, "leak_remaining", false)

	var plugins []*trace.Span
	for _, s := range rt.Spans() {
		if s.Type == trace.SpanPlugin {
			plugins = append(plugins, s)
		}
	}
	require.Len(t, plugins, 1)
	attrs := plugins[0].PluginAttrsCopy()
	assert.Equal(t, "native_bedrock_passthrough", plugins[0].Name)
	assert.Equal(t, "block", attrs.Decision, "the span decision of a refused call")
	assert.Equal(t, "pre_request", attrs.Stage)
	data, ok := attrs.Extras.(*appplugins.NativeMaskData)
	require.True(t, ok)
	assert.Equal(t, "blocked", data.Decision)
	assert.Equal(t, "mask_not_applicable:leak_remaining", data.FailureReason)
	assert.Equal(t, appplugins.DetailAnonymizeNoOutput, data.FailureDetail)
	assert.Equal(t, string(appplugins.ClassOf(appplugins.FailureVerdictIncomplete, data.FailureDetail)), data.FailureClass)
	assert.Equal(t, "input", data.FailureClass)
	assert.True(t, data.Degraded)
	assert.Equal(t, "leak_remaining", data.DegradedReason)
	assert.Contains(t, logs.String(), "mask_not_applicable:leak_remaining")
	assert.Equal(t, 403, plugins[0].StatusCode(), "the call is refused")
}

func TestRecordNativeMaskBlocked_WithoutATraceOnlyLogs(t *testing.T) {
	t.Parallel()
	var logs bytes.Buffer
	appplugins.RecordNativeMaskBlocked(context.Background(), slog.New(slog.NewTextHandler(&logs, nil)), policy.StagePreResponse, "reasoning_not_maskable", true)
	assert.Contains(t, logs.String(), "reasoning_not_maskable")
}
