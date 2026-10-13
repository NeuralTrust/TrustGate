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

package bedrockguardrail

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

func textOf(in *bedrockruntime.ApplyGuardrailInput) string {
	text, _ := in.Content[0].(*types.GuardrailContentBlockMemberText)
	return aws.ToString(text.Value.Text)
}

func benignWords(bytes int) string {
	return strings.Repeat("an ordinary sentence of benign words. ", bytes/38+1)[:bytes]
}

func scripted(apply func(in *bedrockruntime.ApplyGuardrailInput) (*bedrockruntime.ApplyGuardrailOutput, error)) *scriptedGuardrail {
	return &scriptedGuardrail{apply: apply}
}

func TestALongMessageIsSentInChunksOfAtMostTwentyFourUnits(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, benignWords(60000)), nil)
	event, span := eventFor(t)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	require.GreaterOrEqual(t, len(g.inputs), 3)
	for _, text := range g.inputs {
		assert.LessOrEqual(t, len(text), chunkBytes, "24,000 bytes are at most 24 text units, within the smallest burst of 25")
	}
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, len(g.inputs), extras.ChunkCount)
	assert.Equal(t, "allowed", extras.Decision)
}

func TestAMessageAboveTheChunkLimitIsRefusedBeforeAnyCall(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"),
		chatRequestOf(t, benignWords((maxBufferedChunks+1)*chunkBytes)), nil)

	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	assert.Zero(t, g.calls)
}

func blockOnMarker(marker string) *scriptedGuardrail {
	return scripted(func(in *bedrockruntime.ApplyGuardrailInput) (*bedrockruntime.ApplyGuardrailOutput, error) {
		if strings.Contains(textOf(in), marker) {
			return topicBlockedOutput(), nil
		}
		time.Sleep(20 * time.Millisecond)
		return allowOutput(), nil
	})
}

func TestABlockedChunkStopsTheRestInEnforceAndObserveScreensAll(t *testing.T) {
	t.Parallel()
	text := "BLOCKME " + benignWords(100000)
	for _, tc := range []struct {
		mode    policy.Mode
		decided string
	}{{policy.ModeEnforce, "blocked"}, {policy.ModeObserve, "reported"}} {
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			g := blockOnMarker("BLOCKME")
			p := streamPlugin(t, g)
			event, span := eventFor(t)
			in := execInput(policy.StagePreRequest, tc.mode, settingsIn("us-east-1"), chatRequestOf(t, text), nil)
			in.Event = event

			_, err := p.Execute(context.Background(), in)

			extras, ok := span.PluginAttrsCopy().Extras.(*Data)
			require.True(t, ok)
			assert.Equal(t, tc.decided, extras.Decision)
			g.mu.Lock()
			defer g.mu.Unlock()
			if tc.mode == policy.ModeEnforce {
				require.Error(t, err)
				assert.Less(t, g.calls, extras.ChunkCount, "the chunks after the block are skipped")
				return
			}
			require.NoError(t, err)
			assert.Equal(t, extras.ChunkCount, g.calls)
		})
	}
}

func emailMasking() *scriptedGuardrail {
	return scripted(func(in *bedrockruntime.ApplyGuardrailInput) (*bedrockruntime.ApplyGuardrailOutput, error) {
		text := textOf(in)
		if !strings.Contains(text, "@example.com") {
			return allowOutput(), nil
		}
		masked := text
		for _, email := range []string{"first.person@example.com", "second.person@example.com"} {
			masked = strings.ReplaceAll(masked, email, "{EMAIL}")
		}
		return piiAnonymizedOutputWithText(masked), nil
	})
}

func lastMessageOf(t *testing.T, body []byte) string {
	t.Helper()
	var req struct {
		Messages []struct {
			Content string `json:"content"`
		} `json:"messages"`
	}
	require.NoError(t, json.Unmarshal(body, &req))
	return req.Messages[len(req.Messages)-1].Content
}

func TestMasksFromSeveralChunksAreAppliedOnceToTheOriginal(t *testing.T) {
	t.Parallel()
	words := benignWords(90000)
	text := "mail first.person@example.com now " + words[:60000] + " and second.person@example.com too " + words[60000:]
	g := emailMasking()
	p := streamPlugin(t, g)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, text), nil)
	in.Config.Settings["pii_action"] = piiActionAnonymize

	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotEmpty(t, res.RequestBody)
	got := lastMessageOf(t, res.RequestBody)
	assert.Equal(t, strings.NewReplacer("first.person@example.com", "{EMAIL}", "second.person@example.com", "{EMAIL}").Replace(text), got)
}

func TestAnEmailInTheOverlapIsMaskedOnce(t *testing.T) {
	t.Parallel()
	pad := benignWords(chunkBytes - chunkOverlap/2 - 12)
	text := pad + " first.person@example.com " + benignWords(40000)
	g := emailMasking()
	p := streamPlugin(t, g)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, text), nil)
	in.Config.Settings["pii_action"] = piiActionAnonymize

	res, err := p.Execute(context.Background(), in)

	require.NoError(t, err)
	got := lastMessageOf(t, res.RequestBody)
	assert.Equal(t, 1, strings.Count(got, "{EMAIL}"))
	assert.NotContains(t, got, "@example.com")
}

func TestPartialCoverageOnOneChunkRefusesTheRequest(t *testing.T) {
	t.Parallel()
	var call int
	var mu sync.Mutex
	g := scripted(func(*bedrockruntime.ApplyGuardrailInput) (*bedrockruntime.ApplyGuardrailOutput, error) {
		mu.Lock()
		call++
		n := call
		mu.Unlock()
		out := allowOutput()
		if n == 4 {
			out.GuardrailCoverage = &types.GuardrailCoverage{TextCharacters: &types.GuardrailTextCharactersCoverage{
				Guarded: aws.Int32(1000), Total: aws.Int32(24000),
			}}
		}
		return out, nil
	})
	p := streamPlugin(t, g)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, benignWords(100000)), nil)
	in.Event = event

	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, appplugins.DetailCoveragePartial, extras.FailureDetail)
}

// pemLike is a secret as long as a PEM key or a service-account JSON, with the
// line breaks such text has: a chunk may end at one of them, inside the secret.
func pemLike(bytes int) string {
	var b strings.Builder
	b.WriteString("SECRET-BEGIN\n")
	for b.Len() < bytes-len("SECRET-END") {
		b.WriteString(strings.Repeat("k", 63) + "\n")
	}
	b.WriteString("SECRET-END")
	return b.String()
}

// The overlap is what lets a secret that a cut falls inside be seen whole in the
// next chunk: here 3,000 of its 3,500 bytes are in the first chunk.
func TestALongSecretThatACutFallsInsideIsSeenWholeInOneChunk(t *testing.T) {
	t.Parallel()
	g := scripted(func(in *bedrockruntime.ApplyGuardrailInput) (*bedrockruntime.ApplyGuardrailOutput, error) {
		if text := textOf(in); strings.Contains(text, "SECRET-BEGIN") && strings.Contains(text, "SECRET-END") {
			return topicBlockedOutput(), nil
		}
		return allowOutput(), nil
	})
	p := streamPlugin(t, g)
	text := benignWords(chunkBytes-3000) + " " + pemLike(3500) + " " + benignWords(5000)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, text), nil)

	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}
