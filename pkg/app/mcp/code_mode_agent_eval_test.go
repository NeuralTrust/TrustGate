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

//go:build agenteval

package mcp

// The Code Mode agent eval: does a model, given the gateway's tools, write a
// program when a task takes several calls, does the program run, and does
// the answer come out right — and what does it cost compared to calling the
// tools one at a time?
//
// It calls a model API, so it is behind the agenteval build tag and never
// runs in CI. Run it by hand, before and after changing the Code Mode tools'
// descriptions or instructions:
//
//	EVAL_MODEL=<model id> go test -tags agenteval ./pkg/app/mcp -run TestCodeModeAgentEval -v -timeout 30m
//
// The Anthropic client takes its credentials as usual (ANTHROPIC_API_KEY or
// a profile). EVAL_MODES picks the gateway modes to compare (default
// "off,on"), EVAL_TASKS a comma-separated subset of task names, and
// EVAL_REPORT a file to write the results to as JSON.
//
// Each task runs against the real dispatcher (tools/list, the instructions'
// Code Mode sentence, trustgate_search, trustgate_execute, the sandbox) over
// fake Linear, GitHub and Calendar servers with fixed data, and is graded by
// the substrings the right answer must contain.

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/anthropics/anthropic-sdk-go/v2"

	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
)

// evalRun is how one task went.
type evalRun struct {
	Task          string `json:"task"`
	Mode          string `json:"mode"`
	MultiStep     bool   `json:"multi_step"`
	Correct       bool   `json:"correct"`
	Answer        string `json:"answer"`
	ModelCalls    int    `json:"model_tool_calls"`
	Programs      int    `json:"programs"`
	ProgramErrors int    `json:"program_errors"`
	FirstProgram  string `json:"first_program_result,omitempty"`
	Turns         int    `json:"turns"`
	InputTokens   int64  `json:"input_tokens"`
	OutputTokens  int64  `json:"output_tokens"`
	StopReason    string `json:"stop_reason"`
	Error         string `json:"error,omitempty"`
}

const evalSystem = "You are an assistant with access to the user's work tools through their company's MCP gateway. Use the tools to answer; do not guess data you can look up. The gateway's instructions:"

func TestCodeModeAgentEval(t *testing.T) {
	model := os.Getenv("EVAL_MODEL")
	if model == "" {
		t.Skip("set EVAL_MODEL to the model to evaluate")
	}
	modes := strings.Split(envOr("EVAL_MODES", gatewaydomain.MCPCodeModeOff+","+gatewaydomain.MCPCodeModeOn), ",")
	only := map[string]bool{}
	for _, name := range strings.Split(os.Getenv("EVAL_TASKS"), ",") {
		if name = strings.TrimSpace(name); name != "" {
			only[name] = true
		}
	}
	client := anthropic.NewClient()
	w := newEvalWorld(t)

	var runs []evalRun
	for _, mode := range modes {
		mode = strings.TrimSpace(mode)
		for _, task := range evalTasks {
			if len(only) > 0 && !only[task.Name] {
				continue
			}
			run := w.runTask(t, client, model, mode, task)
			runs = append(runs, run)
			t.Logf("%-10s %-22s correct=%-5v calls=%-2d programs=%d (errors %d) turns=%d tokens in/out=%d/%d %s",
				mode, task.Name, run.Correct, run.ModelCalls, run.Programs, run.ProgramErrors, run.Turns, run.InputTokens, run.OutputTokens, run.Error)
		}
	}
	reportAgentEval(t, runs)
	if path := os.Getenv("EVAL_REPORT"); path != "" {
		raw, _ := json.MarshalIndent(runs, "", "  ")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatalf("write report: %v", err)
		}
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// runTask drives the model's tool loop against the dispatcher. It is a
// manual loop because the tools come from tools/list as JSON Schemas and each
// call is dispatched, and counted, as an MCP client would.
func (w evalWorld) runTask(t *testing.T, client anthropic.Client, model, mode string, task evalTask) evalRun {
	t.Helper()
	ctx := w.ctx(mode)
	run := evalRun{Task: task.Name, Mode: mode, MultiStep: task.MultiStep}
	tools, err := w.anthropicTools(ctx)
	if err != nil {
		run.Error = err.Error()
		return run
	}
	system := evalSystem + CodeModeInstructions(ctx, w.rc)
	messages := []anthropic.MessageParam{anthropic.NewUserMessage(anthropic.NewTextBlock(task.Prompt))}
	for run.Turns < 25 {
		run.Turns++
		reqCtx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		resp, err := client.Messages.New(reqCtx, anthropic.MessageNewParams{
			Model:     anthropic.Model(model),
			MaxTokens: 16000,
			System:    []anthropic.TextBlockParam{{Text: system}},
			Messages:  messages,
			Tools:     tools,
		})
		cancel()
		if err != nil {
			run.Error = err.Error()
			return run
		}
		run.InputTokens += resp.Usage.InputTokens + resp.Usage.CacheReadInputTokens + resp.Usage.CacheCreationInputTokens
		run.OutputTokens += resp.Usage.OutputTokens
		run.StopReason = string(resp.StopReason)
		messages = append(messages, resp.ToParam())

		var text strings.Builder
		var uses []anthropic.ToolUseBlock
		for _, block := range resp.Content {
			switch b := block.AsAny().(type) {
			case anthropic.TextBlock:
				text.WriteString(b.Text)
			case anthropic.ToolUseBlock:
				uses = append(uses, b)
			}
		}
		if resp.StopReason == anthropic.StopReasonRefusal {
			run.Error = "refusal"
			return run
		}
		if resp.StopReason != anthropic.StopReasonToolUse {
			run.Answer = text.String()
			run.Correct = graded(run.Answer, task.Want)
			return run
		}
		results := make([]anthropic.ContentBlockParamUnion, len(uses))
		var wg sync.WaitGroup
		var mu sync.Mutex
		for i, use := range uses {
			wg.Add(1)
			go func(i int, use anthropic.ToolUseBlock) {
				defer wg.Done()
				out, isError := w.dispatch(ctx, use.Name, json.RawMessage(use.JSON.Input.Raw()))
				mu.Lock()
				run.ModelCalls++
				if IsCodeModeToolName(use.Name) {
					run.Programs++
					if isError {
						run.ProgramErrors++
					}
					if run.FirstProgram == "" {
						run.FirstProgram = map[bool]string{true: "error", false: "ok"}[isError]
					}
				}
				mu.Unlock()
				results[i] = anthropic.NewToolResultBlock(use.ID, out, isError)
			}(i, use)
		}
		wg.Wait()
		// Every result of the turn goes back in one user message.
		messages = append(messages, anthropic.NewUserMessage(results...))
	}
	run.Error = "too many turns"
	return run
}

// anthropicTools are the tools tools/list offers, as the model gets them.
func (w evalWorld) anthropicTools(ctx context.Context) ([]anthropic.ToolUnionParam, error) {
	listed, err := w.d.Dispatch(ctx, w.rc, "", "tools/list", nil)
	if err != nil {
		return nil, err
	}
	var out []anthropic.ToolUnionParam
	for _, tool := range listed.(map[string]any)["tools"].([]Tool) {
		raw, err := json.Marshal(tool)
		if err != nil {
			return nil, err
		}
		var def struct {
			Name        string `json:"name"`
			Description string `json:"description"`
			InputSchema struct {
				Properties map[string]any `json:"properties"`
				Required   []string       `json:"required"`
			} `json:"inputSchema"`
		}
		if err := json.Unmarshal(raw, &def); err != nil {
			return nil, err
		}
		param := anthropic.ToolParam{
			Name:        def.Name,
			Description: anthropic.String(def.Description),
			InputSchema: anthropic.ToolInputSchemaParam{Properties: def.InputSchema.Properties, Required: def.InputSchema.Required},
		}
		out = append(out, anthropic.ToolUnionParam{OfTool: &param})
	}
	return out, nil
}

func reportAgentEval(t *testing.T, runs []evalRun) {
	t.Helper()
	byMode := map[string][]evalRun{}
	for _, r := range runs {
		byMode[r.Mode] = append(byMode[r.Mode], r)
	}
	modes := make([]string, 0, len(byMode))
	for mode := range byMode {
		modes = append(modes, mode)
	}
	sort.Strings(modes)
	for _, mode := range modes {
		var correct, multi, multiWithProgram, firstOK, withProgram, calls int
		var in, out int64
		for _, r := range byMode[mode] {
			if r.Correct {
				correct++
			}
			if r.MultiStep {
				multi++
				if r.Programs > 0 {
					multiWithProgram++
				}
			}
			if r.Programs > 0 {
				withProgram++
				if r.FirstProgram == "ok" {
					firstOK++
				}
			}
			calls += r.ModelCalls
			in += r.InputTokens
			out += r.OutputTokens
		}
		n := len(byMode[mode])
		t.Logf("%s: correct %d/%d, tool calls %.1f per task, tokens in %d out %d, multi-step tasks with a program %d/%d, first program ran %d/%d",
			mode, correct, n, float64(calls)/float64(n), in, out, multiWithProgram, multi, firstOK, withProgram)
	}
}
