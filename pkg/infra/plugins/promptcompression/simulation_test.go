// Simulation harness: not part of the test suite proper. Run with
//   go test ./pkg/infra/plugins/promptcompression/ -run TestSimulation -v
// It drives the real Execute path over realistic payload classes and reports
// body-level and content-level compression.

package promptcompression

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/require"
)

// --- synthetic payload generators -----------------------------------------

// prettyAPIResponse simulates a pretty-printed REST/tool API response: an
// array of nested records, the shape SmartCrusher-class compressors feast on.
func prettyAPIResponse(rows int) string {
	type record struct {
		ID        int      `json:"id"`
		Name      string   `json:"name"`
		Email     string   `json:"email"`
		Active    bool     `json:"active"`
		Score     float64  `json:"score"`
		Tags      []string `json:"tags"`
		CreatedAt string   `json:"created_at"`
		Metadata  struct {
			Region   string `json:"region"`
			Plan     string `json:"plan"`
			Seats    int    `json:"seats"`
			Owner    string `json:"owner"`
			Internal bool   `json:"internal"`
		} `json:"metadata"`
	}
	records := make([]record, rows)
	for i := range records {
		r := &records[i]
		r.ID = 1000 + i
		r.Name = fmt.Sprintf("Customer %d", i)
		r.Email = fmt.Sprintf("customer%d@example.com", i)
		r.Active = i%3 != 0
		r.Score = float64(i%100) / 7.0
		r.Tags = []string{"enterprise", "eu-west", fmt.Sprintf("cohort-%d", i%5)}
		r.CreatedAt = "2026-07-01T10:00:00Z"
		r.Metadata.Region = "eu-west-1"
		r.Metadata.Plan = "enterprise"
		r.Metadata.Seats = 50 + i
		r.Metadata.Owner = fmt.Sprintf("owner-%d", i%7)
		r.Metadata.Internal = i%9 == 0
	}
	body, _ := json.MarshalIndent(map[string]any{"total": rows, "page": 1, "results": records}, "", "    ")
	return string(body)
}

// ciLog simulates captured CI/terminal output: ANSI color codes, trailing
// whitespace, blank-line runs, duplicated stack frames.
func ciLog(lines int) string {
	var b strings.Builder
	for i := 0; i < lines; i++ {
		switch i % 10 {
		case 0:
			b.WriteString("\x1b[32m✓\x1b[0m test_case_" + fmt.Sprint(i) + " passed   \n")
		case 3:
			b.WriteString("\x1b[31mERROR\x1b[0m: connection refused (attempt " + fmt.Sprint(i) + ")\t\n\n\n\n")
		case 5:
			b.WriteString("    at handler.process (/app/src/handler.js:42:15)   \n")
			b.WriteString("    at Runner.run (/app/node_modules/lib/runner.js:88:3)  \n")
		case 7:
			b.WriteString("\x1b[1;33mWARN\x1b[0m retrying with backoff 2000ms \x1b[90m[req-" + fmt.Sprint(i) + "]\x1b[0m  \n\n")
		default:
			b.WriteString("[2026-07-29T10:00:" + fmt.Sprintf("%02d", i%60) + "Z] worker=" + fmt.Sprint(i%4) + " status=ok latency=12ms\n")
		}
	}
	return b.String()
}

// codeSearchResult simulates an agent tool output: prose with embedded
// pretty-printed fenced JSON blocks (grep/search results as JSON).
func codeSearchResult(blocks int) string {
	var b strings.Builder
	b.WriteString("Found matches in the following files:\n\n")
	for i := 0; i < blocks; i++ {
		b.WriteString(fmt.Sprintf("Match %d in pkg/service/module_%d.go:\n\n```json\n", i+1, i))
		block, _ := json.MarshalIndent(map[string]any{
			"file":  fmt.Sprintf("pkg/service/module_%d.go", i),
			"line":  42 + i*7,
			"match": "func ProcessRequest(ctx context.Context, req *Request) error {",
			"context": []string{
				"// ProcessRequest validates and routes the request",
				"func ProcessRequest(ctx context.Context, req *Request) error {",
				"    if err := req.Validate(); err != nil {",
			},
			"score": 0.92,
		}, "", "  ")
		b.Write(block)
		b.WriteString("\n```\n\nThe function appears to handle validation.   \n\n\n")
	}
	return b.String()
}

// prose simulates a natural-language message with no structure to squeeze.
func prose(paragraphs int) string {
	p := "The gateway processes each request through the configured policy chain. " +
		"Plugins execute at their declared stages and can rewrite, observe, or reject traffic. " +
		"Compression should leave this kind of text essentially untouched."
	var b strings.Builder
	for i := 0; i < paragraphs; i++ {
		b.WriteString(p)
		b.WriteString("\n\n")
	}
	return strings.TrimSuffix(b.String(), "\n")
}

// --- simulation ------------------------------------------------------------

type simCase struct {
	name string
	body []byte
}

func openAIBody(t *testing.T, system string, turns []map[string]any) []byte {
	t.Helper()
	msgs := []map[string]any{}
	if system != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": system})
	}
	msgs = append(msgs, turns...)
	body, err := json.Marshal(map[string]any{"model": "gpt-4o", "messages": msgs})
	require.NoError(t, err)
	return body
}

func TestSimulation(t *testing.T) {
	p := New(adapter.NewRegistry(), nil)
	reg := adapter.NewRegistry()
	set := map[string]any{"max_body_bytes": 0} // uncapped for measurement

	jsonEscape := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}
	_ = jsonEscape

	cases := []simCase{
		{"json_tool_output_50rows", openAIBody(t, "You are a data assistant.", []map[string]any{
			{"role": "user", "content": "fetch the customer list"},
			{"role": "assistant", "content": nil, "tool_calls": []map[string]any{{
				"id": "call_1", "type": "function",
				"function": map[string]any{"name": "list_customers", "arguments": "{\n    \"page\":   1,\n    \"limit\":  50,\n    \"filter\": {\n        \"active\": true\n    }\n}"},
			}}},
			{"role": "tool", "tool_call_id": "call_1", "content": prettyAPIResponse(50)},
			{"role": "user", "content": "summarize the enterprise accounts"},
		})},
		{"json_tool_output_200rows", openAIBody(t, "You are a data assistant.", []map[string]any{
			{"role": "user", "content": "fetch everything"},
			{"role": "tool", "tool_call_id": "call_1", "content": prettyAPIResponse(200)},
		})},
		{"sre_ci_logs_400lines", openAIBody(t, "You are an SRE debugging assistant.", []map[string]any{
			{"role": "user", "content": "why did the deploy fail?"},
			{"role": "tool", "tool_call_id": "call_1", "content": ciLog(400)},
		})},
		{"code_search_20blocks", openAIBody(t, "You are a coding agent.", []map[string]any{
			{"role": "user", "content": "find the request processing entrypoints"},
			{"role": "tool", "tool_call_id": "call_1", "content": codeSearchResult(20)},
		})},
		{"agentic_mixed_conversation", openAIBody(t, "You are a helpful agent."+strings.Repeat(" Follow the team guidelines.", 20), []map[string]any{
			{"role": "user", "content": "investigate the failing service"},
			{"role": "tool", "tool_call_id": "c1", "content": ciLog(120)},
			{"role": "assistant", "content": "The logs show connection errors. Let me check the config."},
			{"role": "tool", "tool_call_id": "c2", "content": prettyAPIResponse(30)},
			{"role": "user", "content": "ok, what's the fix?"},
		})},
		{"prose_only_20paragraphs", openAIBody(t, "You are a writing assistant.", []map[string]any{
			{"role": "user", "content": prose(20)},
		})},
		{"already_compact_json", openAIBody(t, "sys", []map[string]any{
			{"role": "tool", "tool_call_id": "c1", "content": func() string {
				b, _ := json.Marshal(map[string]any{"results": []int{1, 2, 3}})
				return string(b)
			}()},
		})},
	}

	fmt.Printf("\n%-30s %12s %12s %10s %10s %14s\n", "scenario", "bytes_in", "bytes_out", "saved_%", "tok_est_in", "tok_est_saved")
	fmt.Println(strings.Repeat("-", 94))

	for _, c := range cases {
		in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, "", c.body), newEvent())
		res, err := p.Execute(context.Background(), in)
		require.NoError(t, err, c.name)

		out := c.body
		if res.RequestBody != nil {
			out = res.RequestBody
			// verify the compressed body still decodes and is semantically intact
			creq, derr := reg.DecodeRequestFor(out, adapter.FormatOpenAI)
			require.NoError(t, derr, c.name)
			require.NotNil(t, creq, c.name)
		}
		saved := len(c.body) - len(out)
		pct := 100 * float64(saved) / float64(len(c.body))
		fmt.Printf("%-30s %12d %12d %9.1f%% %10d %14d\n",
			c.name, len(c.body), len(out), pct, len(c.body)/4, saved/4)
	}

	// second pass: idempotence at scale — recompressing must be a no-op
	fmt.Println("\nidempotence check (recompress compressed output):")
	for _, c := range cases {
		in := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, "", c.body), newEvent())
		res, _ := p.Execute(context.Background(), in)
		if res.RequestBody == nil {
			continue
		}
		in2 := execInput(policy.StagePreRequest, policy.ModeEnforce, set, reqCtx(openAIProvider, "", res.RequestBody), newEvent())
		res2, err := p.Execute(context.Background(), in2)
		require.NoError(t, err)
		require.Nil(t, res2.RequestBody, "%s: recompression must be a no-op", c.name)
	}
	fmt.Println("  all compressed outputs are fixed points ✓")
}
