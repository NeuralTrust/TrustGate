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

package promptdecorator_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/NeuralTrust/TrustGate/pkg/infra/plugins/promptdecorator"
	"github.com/stretchr/testify/require"
)

type compositionPlugin struct {
	name       string
	mutatesReq bool
	execute    func(appplugins.ExecInput) (*appplugins.Result, error)
}

func (p *compositionPlugin) Name() string {
	return p.name
}

func (p *compositionPlugin) MandatoryStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *compositionPlugin) SupportedStages() []policy.Stage {
	return []policy.Stage{policy.StagePreRequest}
}

func (p *compositionPlugin) SupportedModes() []policy.Mode {
	return []policy.Mode{policy.ModeEnforce}
}

func (p *compositionPlugin) ValidateConfig(map[string]any) error {
	return nil
}

func (p *compositionPlugin) MutatesRequestBody() bool {
	return p.mutatesReq
}

func (p *compositionPlugin) MutatesResponseBody() bool {
	return false
}

func (p *compositionPlugin) MutatesMetadata() bool {
	return false
}

func (p *compositionPlugin) Execute(_ context.Context, in appplugins.ExecInput) (*appplugins.Result, error) {
	return p.execute(in)
}

type compositionMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type compositionDocument struct {
	Messages []compositionMessage `json:"messages"`
}

type capturedRequest struct {
	request      *infracontext.RequestContext
	body         []byte
	originalBody []byte
}

func TestCompositionFoldsAroundPromptDecoratorWithoutContextWrites(t *testing.T) {
	t.Parallel()

	originalBody := []byte(`{"messages":[{"role":"system","content":"client-system"},{"role":"user","content":"client-user"}]}`)
	body := append([]byte(nil), originalBody...)
	bodyBefore := append([]byte(nil), body...)
	originalBefore := append([]byte(nil), body...)
	probeInput := make(chan capturedRequest, 2)
	followingInput := make(chan capturedRequest, 1)
	started := make(chan string, 2)
	release := make(chan struct{})

	preceding := replaceMessagesPlugin("a_preceding", []compositionMessage{
		{Role: "user", Content: "preceding"},
	})
	reader := func(name string) *compositionPlugin {
		return &compositionPlugin{
			name: name,
			execute: func(in appplugins.ExecInput) (*appplugins.Result, error) {
				probeInput <- captureRequest(in.Request)
				started <- name
				<-release
				return &appplugins.Result{StatusCode: http.StatusOK}, nil
			},
		}
	}
	firstReader := reader("b_read_only")
	lastReader := reader("zz_read_only")
	following := appendMessagePlugin("z_following")
	following.execute = func(in appplugins.ExecInput) (*appplugins.Result, error) {
		followingInput <- captureRequest(in.Request)
		return appendConfiguredMessage(in)
	}

	registry := compositionRegistry(t, preceding, firstReader, promptdecorator.New(), lastReader, following)
	policies := []*policy.Policy{
		compositionPolicy(t, "00000000-0000-0000-0000-000000000005", following.Name(), 30, true, messageSettings("assistant", "following")),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000003", promptdecorator.PluginName, 20, true, decoratorSettings("decorated", true)),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000004", lastReader.Name(), 20, true, nil),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000001", preceding.Name(), 10, true, nil),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000002", firstReader.Name(), 20, true, nil),
	}
	req := &infracontext.RequestContext{
		Body:         body,
		SourceFormat: "openai",
		Headers:      map[string][]string{"X-Test": {"original"}},
		Metadata:     map[string]interface{}{"tenant": "consumer"},
	}

	type runResult struct {
		outcome *appplugins.StageOutcome
		err     error
	}
	done := make(chan runResult, 1)
	go func() {
		outcome, err := appplugins.NewExecutor(registry, nil).RunStage(context.Background(), appplugins.StageInput{
			Stage:    policy.StagePreRequest,
			Plan:     appplugins.NewStagePlan(registry, policies, nil),
			Request:  req,
			Response: &infracontext.ResponseContext{},
		})
		done <- runResult{outcome: outcome, err: err}
	}()
	startedReaders := make(map[string]struct{}, 2)
	for range 2 {
		select {
		case name := <-started:
			startedReaders[name] = struct{}{}
		case <-time.After(time.Second):
			close(release)
			t.Fatal("read-only plugins did not run in the same parallel batch")
		}
	}
	close(release)
	result := <-done
	require.NoError(t, result.err)
	require.False(t, result.outcome.ShortCircuit)
	require.Equal(t, map[string]struct{}{
		"b_read_only":  {},
		"zz_read_only": {},
	}, startedReaders)

	firstProbe := <-probeInput
	secondProbe := <-probeInput
	followingSeen := <-followingInput
	require.NotSame(t, req, firstProbe.request)
	require.NotSame(t, req, secondProbe.request)
	require.NotSame(t, firstProbe.request, secondProbe.request)
	require.Equal(t, []string{"preceding"}, messageContents(t, firstProbe.body))
	require.Equal(t, []string{"preceding"}, messageContents(t, secondProbe.body))
	require.Equal(t, []string{"preceding", "decorated"}, messageContents(t, followingSeen.body))
	require.Equal(t, originalBefore, firstProbe.originalBody)
	require.Equal(t, originalBefore, secondProbe.originalBody)
	require.Equal(t, originalBefore, followingSeen.originalBody)
	require.Equal(t, []string{"preceding", "decorated", "following"}, messageContents(t, req.Body))
	require.Equal(t, originalBefore, req.OriginalBody)
	require.Equal(t, bodyBefore, body)

	firstProbe.request.Headers["X-Captured"] = []string{"first"}
	firstProbe.request.Metadata["captured"] = "first"
	secondProbe.request.Headers["X-Second"] = []string{"second"}
	secondProbe.request.Metadata["second"] = "second"
	require.Equal(t, []string{"original"}, req.Headers["X-Test"])
	require.Equal(t, "consumer", req.Metadata["tenant"])
	require.NotContains(t, req.Headers, "X-Captured")
	require.NotContains(t, req.Headers, "X-Second")
	require.NotContains(t, req.Metadata, "captured")
	require.NotContains(t, req.Metadata, "second")
}

func TestCompositionRejectsSystemInjectedAfterOriginalSnapshot(t *testing.T) {
	t.Parallel()

	original := []byte(`{"messages":[{"role":"user","content":"client-user"}]}`)
	originalBefore := append([]byte(nil), original...)
	preceding := replaceMessagesPlugin("a_inject_system", []compositionMessage{
		{Role: "system", Content: "injected"},
		{Role: "user", Content: "folded"},
	})
	var followingCalls int32
	following := appendMessagePlugin("z_following")
	following.execute = func(in appplugins.ExecInput) (*appplugins.Result, error) {
		atomic.AddInt32(&followingCalls, 1)
		return appendConfiguredMessage(in)
	}
	registry := compositionRegistry(t, preceding, promptdecorator.New(), following)
	policies := []*policy.Policy{
		compositionPolicy(t, "00000000-0000-0000-0000-000000000003", following.Name(), 30, true, messageSettings("assistant", "unreachable")),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000001", preceding.Name(), 10, true, nil),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000002", promptdecorator.PluginName, 20, true, map[string]any{"require_system_message": true}),
	}
	req := &infracontext.RequestContext{
		Body:         original,
		SourceFormat: "openai",
	}

	outcome, err := appplugins.NewExecutor(registry, nil).RunStage(context.Background(), appplugins.StageInput{
		Stage:    policy.StagePreRequest,
		Plan:     appplugins.NewStagePlan(registry, policies, nil),
		Request:  req,
		Response: &infracontext.ResponseContext{},
	})
	require.Nil(t, outcome)
	pluginError, ok := appplugins.AsPluginError(err)
	require.True(t, ok)
	require.Equal(t, http.StatusBadRequest, pluginError.StatusCode)
	require.Equal(t, "system_message_required", pluginError.Type)
	require.Equal(t, []byte(`{"error":{"type":"system_message_required"}}`), pluginError.Body)
	require.Equal(t, []string{"injected", "folded"}, messageContents(t, req.Body))
	require.Equal(t, originalBefore, req.OriginalBody)
	require.Equal(t, int32(0), atomic.LoadInt32(&followingCalls))
}

func TestCompositionParallelBodyMutatorsOrderByPrioritySlugAndID(t *testing.T) {
	t.Parallel()

	alpha := appendMessagePlugin("alpha_mutator")
	omega := appendMessagePlugin("zz_mutator")
	priorityFirst := appendMessagePlugin("zz_priority_first")
	registry := compositionRegistry(t, alpha, omega, priorityFirst, promptdecorator.New())
	policies := []*policy.Policy{
		compositionPolicy(t, "00000000-0000-0000-0000-000000000002", alpha.Name(), 20, true, messageSettings("assistant", "id-2")),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000005", omega.Name(), 20, true, messageSettings("assistant", "slug-last")),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000003", promptdecorator.PluginName, 20, true, decoratorSettings("decorated", false)),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000001", alpha.Name(), 20, true, messageSettings("assistant", "id-1")),
		compositionPolicy(t, "00000000-0000-0000-0000-000000000004", priorityFirst.Name(), 10, true, messageSettings("assistant", "priority-first")),
	}
	expected := []string{"initial", "priority-first", "id-1", "id-2", "decorated", "slug-last"}

	for run := 0; run < 25; run++ {
		shift := run % len(policies)
		shuffled := append(append([]*policy.Policy(nil), policies[shift:]...), policies[:shift]...)
		initial := []byte(`{"messages":[{"role":"user","content":"initial"}]}`)
		req := &infracontext.RequestContext{
			Body:         append([]byte(nil), initial...),
			OriginalBody: append([]byte(nil), initial...),
			SourceFormat: "openai",
		}
		_, err := appplugins.NewExecutor(registry, nil).RunStage(context.Background(), appplugins.StageInput{
			Stage:    policy.StagePreRequest,
			Plan:     appplugins.NewStagePlan(registry, shuffled, nil),
			Request:  req,
			Response: &infracontext.ResponseContext{},
		})
		require.NoError(t, err)
		require.Equal(t, expected, messageContents(t, req.Body), "run %d", run)
		require.Equal(t, initial, req.OriginalBody)
	}
}

func compositionRegistry(t *testing.T, plugins ...appplugins.Plugin) appplugins.Registry {
	t.Helper()
	registry := appplugins.NewRegistry()
	for _, plugin := range plugins {
		require.NoError(t, registry.Register(plugin))
	}
	return registry
}

func compositionPolicy(
	t *testing.T,
	id string,
	slug string,
	priority int,
	parallel bool,
	settings map[string]any,
) *policy.Policy {
	t.Helper()
	policyID, err := ids.Parse[ids.PolicyKind](id)
	require.NoError(t, err)
	return &policy.Policy{
		ID:       policyID,
		Name:     slug,
		Slug:     slug,
		Enabled:  true,
		Priority: priority,
		Parallel: parallel,
		Settings: settings,
		Stages:   []policy.Stage{policy.StagePreRequest},
		Mode:     policy.ModeEnforce,
	}
}

func decoratorSettings(content string, requireSystem bool) map[string]any {
	settings := map[string]any{
		"decorators": []any{
			map[string]any{
				"position": "end",
				"role":     "assistant",
				"content":  content,
			},
		},
	}
	if requireSystem {
		settings["require_system_message"] = true
	}
	return settings
}

func messageSettings(role, content string) map[string]any {
	return map[string]any{"role": role, "content": content}
}

func appendMessagePlugin(name string) *compositionPlugin {
	return &compositionPlugin{
		name:       name,
		mutatesReq: true,
		execute:    appendConfiguredMessage,
	}
}

func replaceMessagesPlugin(name string, messages []compositionMessage) *compositionPlugin {
	return &compositionPlugin{
		name:       name,
		mutatesReq: true,
		execute: func(appplugins.ExecInput) (*appplugins.Result, error) {
			body, err := json.Marshal(compositionDocument{Messages: messages})
			if err != nil {
				return nil, fmt.Errorf("marshal replacement body: %w", err)
			}
			return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
		},
	}
}

func appendConfiguredMessage(in appplugins.ExecInput) (*appplugins.Result, error) {
	if in.Request == nil {
		return nil, fmt.Errorf("missing request")
	}
	role, roleOK := in.Config.Settings["role"].(string)
	content, contentOK := in.Config.Settings["content"].(string)
	if !roleOK || !contentOK {
		return nil, fmt.Errorf("invalid message settings")
	}
	var document compositionDocument
	if err := json.Unmarshal(in.Request.Body, &document); err != nil {
		return nil, fmt.Errorf("decode request body: %w", err)
	}
	document.Messages = append(document.Messages, compositionMessage{Role: role, Content: content})
	body, err := json.Marshal(document)
	if err != nil {
		return nil, fmt.Errorf("encode request body: %w", err)
	}
	return &appplugins.Result{StatusCode: http.StatusOK, RequestBody: body}, nil
}

func captureRequest(req *infracontext.RequestContext) capturedRequest {
	return capturedRequest{
		request:      req,
		body:         append([]byte(nil), req.Body...),
		originalBody: append([]byte(nil), req.OriginalBody...),
	}
}

func messageContents(t *testing.T, body []byte) []string {
	t.Helper()
	var document compositionDocument
	require.NoError(t, json.Unmarshal(body, &document))
	contents := make([]string, len(document.Messages))
	for index, message := range document.Messages {
		contents[index] = message.Content
	}
	return contents
}
