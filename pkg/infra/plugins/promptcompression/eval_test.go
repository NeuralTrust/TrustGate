//go:build eval

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

package promptcompression

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
	"github.com/stretchr/testify/require"
)

// evalConfigs are the plugin settings the evaluation compares. "default" is
// the production configuration (no settings); the single-transform variants
// attribute the savings to each transform, and min_length_0 shows what the
// 256-byte floor leaves on the table.
var evalConfigs = []struct {
	name     string
	settings map[string]any
}{
	{"default", map[string]any{}},
	{"json_only", map[string]any{"normalize_whitespace": false, "strip_ansi": false}},
	{"whitespace_only", map[string]any{"compress_json": false, "strip_ansi": false}},
	{"ansi_only", map[string]any{"compress_json": false, "normalize_whitespace": false}},
	{"min_length_0", map[string]any{"min_length": 0}},
}

type evalRequest struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Provider string `json:"provider"`
	Body     string `json:"body"`
}

type evalResult struct {
	ID         string `json:"id"`
	Category   string `json:"category"`
	Config     string `json:"config"`
	Decision   string `json:"decision"`
	BytesIn    int    `json:"bytes_in"`
	BytesOut   int    `json:"bytes_out"`
	DurationNS int64  `json:"duration_ns"`
	BodyOut    string `json:"body_out,omitempty"`
}

// TestCompressionEval runs the plugin's real Execute path over every request
// in a corpus built by scripts/eval/promptcompression/build_corpus.py and
// writes one results_<config>.jsonl per configuration. It only runs under the
// eval build tag with both environment variables set; see
// scripts/eval/promptcompression/run.sh.
func TestCompressionEval(t *testing.T) {
	corpusPath := os.Getenv("PROMPT_COMPRESSION_EVAL_CORPUS")
	outDir := os.Getenv("PROMPT_COMPRESSION_EVAL_OUT")
	if corpusPath == "" || outDir == "" {
		t.Skip("set PROMPT_COMPRESSION_EVAL_CORPUS and PROMPT_COMPRESSION_EVAL_OUT to run the evaluation")
	}
	requests := loadEvalCorpus(t, corpusPath)
	require.NotEmpty(t, requests)
	require.NoError(t, os.MkdirAll(outDir, 0o755))

	p := New(adapter.NewRegistry(), nil)
	for _, cfg := range evalConfigs {
		f, err := os.Create(filepath.Join(outDir, "results_"+cfg.name+".jsonl"))
		require.NoError(t, err)
		w := bufio.NewWriterSize(f, 1<<20)
		enc := json.NewEncoder(w)
		for _, r := range requests {
			res := runEvalRequest(t, p, cfg.name, cfg.settings, r)
			require.NoError(t, enc.Encode(res))
		}
		require.NoError(t, w.Flush())
		require.NoError(t, f.Close())
		t.Logf("%s: %d requests", cfg.name, len(requests))
	}
}

func runEvalRequest(t *testing.T, p *Plugin, name string, settings map[string]any, r evalRequest) evalResult {
	t.Helper()
	body := []byte(r.Body)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settings, reqCtx(r.Provider, "", body), nil)
	start := time.Now()
	res, err := p.Execute(context.Background(), in)
	elapsed := time.Since(start)
	require.NoError(t, err, r.ID)

	out := evalResult{
		ID:         r.ID,
		Category:   r.Category,
		Config:     name,
		Decision:   "passthrough",
		BytesIn:    len(body),
		BytesOut:   len(body),
		DurationNS: elapsed.Nanoseconds(),
	}
	if d := res.Headers[headerDecision]; len(d) > 0 {
		out.Decision = d[0]
	}
	if res.RequestBody != nil {
		out.BytesOut = len(res.RequestBody)
		out.BodyOut = string(res.RequestBody)
	}
	return out
}

func loadEvalCorpus(t *testing.T, path string) []evalRequest {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	dec := json.NewDecoder(bufio.NewReaderSize(f, 1<<20))
	var out []evalRequest
	for {
		var r evalRequest
		err := dec.Decode(&r)
		if errors.Is(err, io.EOF) {
			return out
		}
		require.NoError(t, err)
		out = append(out, r)
	}
}
