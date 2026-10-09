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

package trustguard

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/pluginutil"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// requestWith builds an OpenAI chat request whose user turn is text followed by
// the given content parts, in the documented image_url shape.
func requestWith(t *testing.T, text string, imageURLs ...string) *infracontext.RequestContext {
	t.Helper()
	content := []map[string]any{{"type": "text", "text": text}}
	for _, u := range imageURLs {
		content = append(content, map[string]any{"type": "image_url", "image_url": map[string]any{"url": u}})
	}
	raw, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": []map[string]any{{"role": "user", "content": content}}})
	require.NoError(t, err)
	req := requestContext()
	req.Body = raw
	return req
}

func dataURL(size int) string {
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString([]byte(strings.Repeat("\x89", size)))
}

func attachmentsOf(t *testing.T, payload json.RawMessage) []GuardAttachment {
	t.Helper()
	var p struct {
		Attachments []GuardAttachment `json:"attachments"`
	}
	require.NoError(t, json.Unmarshal(payload, &p))
	return p.Attachments
}

// An image is not text: the ceiling counts what a model reads, so a 2 MiB text
// with a 3 MiB image is evaluated whole.
func TestATextAndAnImageAreEvaluatedWhenOnlyTheTextCounts(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := requestWith(t, strings.Repeat("a", 2<<20), dataURL(3<<20))
	event, span := newEvent()

	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event))

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, f.count())
	sent := attachmentsOf(t, f.captured().Payload)
	require.Len(t, sent, 1)
	assert.Greater(t, len(sent[0].Data), 3<<20)
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, decisionAllowed, extras.Decision)
}

// A 300 KiB agent session whose JSON is heavier than 512 KiB once escaped is
// text well under the ceiling.
func TestAnEscapeHeavyAgentSessionIsEvaluated(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := chatRequestOf(t, strings.Repeat("<", 300<<10))

	res, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, f.count())
}

func TestTheCeilingCountsToolCallArgumentsAndToolDefinitions(t *testing.T) {
	t.Parallel()
	creq := &adapter.CanonicalRequest{
		System: "sys",
		Messages: []adapter.CanonicalMessage{
			{Role: "user", Content: "hello"},
			{Role: "assistant", ToolCalls: []adapter.CanonicalToolCall{{Name: "search", Arguments: `{"q":"abc"}`}}},
		},
		Tools: []adapter.CanonicalTool{{Name: "search", Description: " finds things ", Schema: map[string]any{"type": "object"}}},
	}
	assert.Equal(t, len("sys")+len("hello")+len(`{"q":"abc"}`)+len("search")+len("finds things")+len(`{"type":"object"}`), requestTextBytes(creq))
	assert.Equal(t, 0, requestTextBytes(nil))
}

// A transform answers with the payload echoed back, so an answer as large as the
// text it was sent is what a faithful echo is, and must not be read as too large.
func TestATransformEchoOfALargeTextIsAccepted(t *testing.T) {
	t.Parallel()
	text := strings.Repeat("an ordinary sentence. ", (5<<19)/22) + " victim@example.com"
	require.Greater(t, len(text), 2<<20+400<<10)
	f := &fakeGuard{echoMask: func(s string) string { return strings.ReplaceAll(s, "victim@example.com", "[EMAIL]") }}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	event, span := newEvent()

	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), chatRequestOf(t, text), nil, event))

	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.RequestBody)
	assert.NotContains(t, string(res.RequestBody), "victim@example.com")
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, decisionTransformed, extras.Decision)
}

func TestAnswerLimitScalesWithThePayloadSent(t *testing.T) {
	t.Parallel()
	assert.Equal(t, maxResponseBytes, answerLimit(1000))
	assert.Equal(t, 2*(3<<20)+answerSlackBytes, answerLimit(3<<20))
}

// TrustGuard answers 400 "invalid attachment" for every attachment it cannot
// resolve, a URL it could not fetch included. The text is evaluated again
// without the URL attachments and what was left out is recorded.
func TestAnInvalidAttachmentOnAURLRetriesWithoutIt(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var seen [][]GuardAttachment
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	f.preflight = func(body GuardRequest) (int, string) {
		attachments := attachmentsOf(t, body.Payload)
		mu.Lock()
		seen = append(seen, attachments)
		mu.Unlock()
		for _, a := range attachments {
			if a.URL != "" {
				return http.StatusBadRequest, invalidAttachmentBody
			}
		}
		return 0, ""
	}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := requestWith(t, "what is in these pictures?", "https://cdn.example.com/down.png", dataURL(64))
	event, span := newEvent()

	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event))

	require.NoError(t, err)
	require.NotNil(t, res)
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, seen, 2)
	assert.Len(t, seen[0], 2, "the first call carries the URL and the data attachment")
	require.Len(t, seen[1], 1, "the second call has no URL")
	assert.Empty(t, seen[1][0].URL)
	assert.NotEmpty(t, seen[1][0].Data)
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, decisionAllowed, extras.Decision, "the text was evaluated and its verdict is applied")
	assert.Equal(t, 1, extras.AttachmentsNotFetched)
	assert.Equal(t, 1, extras.AttachmentsNotInspected)
	assert.Equal(t, failureReasonVerdictIncomplete, extras.FailureReason, "part of the request was never inspected, which alerts")
	assert.Equal(t, appplugins.DetailAttachmentNotFetched, extras.FailureDetail)
	assert.Equal(t, "availability", extras.FailureClass)
	raw, err := json.Marshal(extras)
	require.NoError(t, err)
	assert.Contains(t, string(raw), `"attachments_not_fetched":1`)
	assert.Contains(t, string(raw), `"failure_reason":"verdict_incomplete"`)
	assert.Contains(t, string(raw), `"failure_detail":"attachment_not_fetched"`)
}

// A verdict on the text that comes back from the second call is applied: a block
// still blocks, and the not-fetched attachment is recorded beside it.
func TestAVerdictFromTheRetryWithoutTheURLIsStillApplied(t *testing.T) {
	t.Parallel()
	f := blockingGuard()
	f.preflight = func(body GuardRequest) (int, string) {
		for _, a := range attachmentsOf(t, body.Payload) {
			if a.URL != "" {
				return http.StatusBadRequest, invalidAttachmentBody
			}
		}
		return 0, ""
	}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := requestWith(t, jailbreakText, "https://cdn.example.com/down.png")
	event, span := newEvent()

	_, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event))

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, typeBlocked, pe.Type)
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, decisionBlocked, extras.Decision)
	assert.Equal(t, appplugins.DetailAttachmentNotFetched, extras.FailureDetail)
	assert.Equal(t, 1, extras.AttachmentsNotFetched)
}

func TestTheRetryNeedsItsMinimumShareOfTheBudget(t *testing.T) {
	t.Parallel()
	start := time.Unix(1_700_000_000, 0)
	budget := 4 * time.Second

	deadline := start.Add(budget)
	assert.True(t, retryHasBudget(start.Add(3*time.Second), deadline, budget))
	assert.False(t, retryHasBudget(start.Add(3*time.Second+time.Millisecond), deadline, budget), "less than the minimum share is left")
	assert.False(t, retryHasBudget(deadline.Add(time.Second), deadline, budget))
}

func TestASecondInvalidAttachmentIsInput(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	f.preflight = func(GuardRequest) (int, string) { return http.StatusBadRequest, invalidAttachmentBody }
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := requestWith(t, "look", "https://cdn.example.com/down.png", dataURL(64))
	event, span := newEvent()

	_, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event))

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	assert.Equal(t, 2, f.count(), "one retry without the URL, and no more")
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, "input", extras.FailureClass)
	assert.Equal(t, failureReasonAttachmentRejected, extras.FailureReason)
}

func TestAnInvalidAttachmentWithNoURLIsInputAtOnce(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	f.preflight = func(GuardRequest) (int, string) { return http.StatusBadRequest, invalidAttachmentBody }
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := requestWith(t, "look", dataURL(64))

	_, err := p.Execute(context.Background(), execInput(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil))

	_, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, 1, f.count())
}

// A Gemini Files URI answers only to the key of the caller that uploaded the
// file, which TrustGuard does not have: it is never sent, and counted as not
// fetched instead of as a rejection.
func TestAGeminiFilesURIIsNeverSent(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := requestWith(t, "summarise", "https://generativelanguage.googleapis.com/v1beta/files/abc-123")
	event, span := newEvent()

	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event))

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, f.count())
	assert.Empty(t, attachmentsOf(t, f.captured().Payload))
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, 1, extras.AttachmentsNotFetched)
	assert.Equal(t, 1, extras.AttachmentsNotInspected)
	assert.Equal(t, appplugins.DetailAttachmentNotFetched, extras.FailureDetail)
	assert.Equal(t, "availability", extras.FailureClass)
}

// The gateway and TrustGuard's resolver agree byte for byte: a part carrying
// both a url and data is rejected by the resolver, whatever whitespace data is.
func TestResolvableAttachmentComparesTheFieldsAsSent(t *testing.T) {
	t.Parallel()
	assert.False(t, resolvableAttachment(GuardAttachment{URL: "https://a.example/b.png", Data: " "}))
	assert.False(t, resolvableAttachment(GuardAttachment{Data: " "}))
	assert.True(t, resolvableAttachment(GuardAttachment{URL: "https://a.example/b.png"}))
	assert.False(t, resolvableAttachment(GuardAttachment{URL: "https://generativelanguage.googleapis.com/v1beta/files/x"}))
	assert.True(t, resolvableAttachment(GuardAttachment{URL: "https://generativelanguage.googleapis.com/v1beta/models/x"}))
}

func TestReasonOfErrorMapsEveryFailureOfTheEvaluateCall(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
		want string
	}{
		{"answer too large", &pluginutil.AnswerTooLargeError{Provider: "trustguard", Limit: 1}, failureReasonResponseTooLarge},
		{"payload too large", &payloadTooLargeError{}, failureReasonPayloadTooLarge},
		{"attachment", &attachmentRejectedError{}, failureReasonAttachmentRejected},
		{"entitlements", &entitlementsUnavailableError{}, failureReasonEntitlementsUnavailable},
		{"auth", &authRejectedError{status: 403}, failureReasonUnauthorized},
		{"unauthorized", errUnauthorized, failureReasonUnauthorized},
		{"deadline", context.DeadlineExceeded, failureReasonTimeout},
		{"anything else", errors.New("connection reset"), failureReasonTransport},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, reasonOfError(context.Background(), tc.err))
		})
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	assert.Equal(t, failureReasonTransport, reasonOfError(cancelled, context.DeadlineExceeded),
		"a deadline the caller's own context ended is not the guard running out of time")
}

// The first call has the whole budget whatever the request carries: a slow answer
// that comes back inside the budget is applied, not cut at three quarters of it
// to keep a share for a retry that may never be needed.
func TestASlowSuccessfulFirstCallWithAURLAttachmentIsNotCutEarly(t *testing.T) {
	t.Parallel()
	f := &fakeGuard{response: GuardResponse{Status: statusAllow}, delay: testTimeout * 17 / 20}
	p := newTestPlugin(t, adapter.NewRegistry(), newServer(t, f).URL)
	req := requestWith(t, "what is in this picture?", "https://cdn.example.com/slow.png")
	event, span := newEvent()

	res, err := p.Execute(context.Background(), execInputWithEvent(policy.StagePreRequest, policy.ModeEnforce, settings(""), req, nil, event))

	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, 1, f.count())
	extras, ok := span.PluginAttrsCopy().Extras.(guardData)
	require.True(t, ok)
	assert.Equal(t, decisionAllowed, extras.Decision)
	assert.Empty(t, extras.FailureReason, "the answer was not cut")
}
