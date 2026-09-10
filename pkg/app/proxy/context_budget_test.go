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

package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type budgetCatalog struct {
	model *catalogdomain.Model
	err   error
}

func (c budgetCatalog) FindModel(_ context.Context, _, _ string) (*catalogdomain.Model, error) {
	if c.err != nil {
		return nil, c.err
	}
	return c.model, nil
}

func TestEstimateRequestTextBytes(t *testing.T) {
	prose := `{"messages":[{"content":"` + strings.Repeat("hello world ", 20) + `"}]}`
	schema := `{"tools":[{"function":{"parameters":{"type":"object","properties":{"q":{"type":"string","description":"` + strings.Repeat("arg ", 40) + `"}}}}}]}`
	cjk := `{"messages":[{"content":"` + strings.Repeat("日本語テスト", 30) + `"}]}`
	b64 := strings.Repeat("A", 2048)
	image := `{"messages":[{"content":"data:image/png;base64,` + b64 + `"}]}`
	blob := `{"messages":[{"content":"` + b64 + `"}]}`
	spaces := `{"messages":[{"content":"` + strings.Repeat("a   b   c   ", 50) + `"}]}`

	cases := []struct {
		name string
		body string
		skip int
	}{
		{"prose", prose, 0},
		{"json schema", schema, 0},
		{"cjk", cjk, 0},
		{"data uri skipped", image, 0},
		{"base64 blob skipped", blob, 0},
		{"whitespace collapsed", spaces, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			total, _ := estimateRequestTextBytes([]byte(tc.body))
			assert.GreaterOrEqual(t, total, 0)
			if strings.Contains(tc.name, "skipped") {
				assert.Equal(t, 0, total)
			}
		})
	}
}

func TestCheckContextBudget_NoFalsePositiveAroundWindow(t *testing.T) {
	window := 100
	p := &providerInvoker{
		catalog: budgetCatalog{model: &catalogdomain.Model{ContextWindow: window}},
		logger:  slog.Default(),
	}
	pad := strings.Repeat("x", int(1.4*float64(window)*contextBytesPerToken))
	body, err := json.Marshal(map[string]any{
		"messages": []map[string]string{{"role": "user", "content": pad}},
	})
	require.NoError(t, err)
	require.Greater(t, len(body), contextBytesPerToken*window)
	prep := &preparedInvocation{
		capability:   capabilityChat,
		providerName: "openai",
		sentModel:    "gpt-4",
		body:         body,
	}
	original := append([]byte(nil), body...)
	require.NoError(t, p.checkContextBudget(context.Background(), prep))
	assert.Equal(t, original, prep.body)
}

func TestCheckContextBudget_RejectsTripleWindow(t *testing.T) {
	window := 100
	p := &providerInvoker{
		catalog: budgetCatalog{model: &catalogdomain.Model{ContextWindow: window}},
		logger:  slog.Default(),
	}
	pad := strings.Repeat("tool-schema ", 2000)
	body, err := json.Marshal(map[string]any{
		"tools": []map[string]any{{"name": "lookup", "description": pad}},
	})
	require.NoError(t, err)
	prep := &preparedInvocation{
		capability:   capabilityChat,
		providerName: "openai",
		sentModel:    "gpt-4",
		body:         body,
	}
	err = p.checkContextBudget(context.Background(), prep)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrContextWindowExceeded))
	assert.Contains(t, err.Error(), "100")
}

func TestCheckContextBudget_SkipsWhenDisabled(t *testing.T) {
	huge := bytes.Repeat([]byte("x"), 100_000)
	body := []byte(`{"messages":[{"content":"` + string(huge) + `"}]}`)
	cases := []struct {
		name string
		p    *providerInvoker
		prep *preparedInvocation
	}{
		{
			name: "nil catalog",
			p:    &providerInvoker{logger: slog.Default()},
			prep: &preparedInvocation{capability: capabilityChat, providerName: "openai", sentModel: "gpt-4", body: body},
		},
		{
			name: "zero window",
			p:    &providerInvoker{catalog: budgetCatalog{model: &catalogdomain.Model{ContextWindow: 0}}, logger: slog.Default()},
			prep: &preparedInvocation{capability: capabilityChat, providerName: "openai", sentModel: "gpt-4", body: body},
		},
		{
			name: "openai compatible",
			p:    &providerInvoker{catalog: budgetCatalog{model: &catalogdomain.Model{ContextWindow: 8192}}, logger: slog.Default()},
			prep: &preparedInvocation{capability: capabilityChat, providerName: provider.OpenAICompatible, sentModel: "local", body: body},
		},
		{
			name: "embeddings",
			p:    &providerInvoker{catalog: budgetCatalog{model: &catalogdomain.Model{ContextWindow: 8192}}, logger: slog.Default()},
			prep: &preparedInvocation{capability: capabilityEmbeddings, providerName: "openai", sentModel: "gpt-4", body: body},
		},
		{
			name: "lookup error",
			p:    &providerInvoker{catalog: budgetCatalog{err: errors.New("missing")}, logger: slog.Default()},
			prep: &preparedInvocation{capability: capabilityChat, providerName: "openai", sentModel: "gpt-4", body: body},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.NoError(t, tc.p.checkContextBudget(context.Background(), tc.prep))
		})
	}
}
