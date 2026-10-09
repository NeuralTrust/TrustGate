// Copyright 2026 NeuralTrust
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package bedrockguardrail

import (
	"context"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/bedrockruntime"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

// latencyGuardrail answers after a real delay and gives up when its context
// ends, as a network call does: it is what shows how long a request's own
// chunks take, which a fake that answers at once cannot.
type latencyGuardrail struct {
	delay  time.Duration
	hang   string
	block  string
	calls  atomic.Int32
	answer func() (*bedrockruntime.ApplyGuardrailOutput, error)
}

func (g *latencyGuardrail) ApplyGuardrail(
	ctx context.Context,
	in *bedrockruntime.ApplyGuardrailInput,
	_ ...func(*bedrockruntime.Options),
) (*bedrockruntime.ApplyGuardrailOutput, error) {
	g.calls.Add(1)
	text := textOf(in)
	if g.hang != "" && strings.Contains(text, g.hang) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	select {
	case <-time.After(g.delay):
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if g.answer != nil {
		return g.answer()
	}
	if g.block != "" && strings.Contains(text, g.block) {
		return topicBlockedOutput(), nil
	}
	return allowOutput(), nil
}

func pluginOver(g guardrailClient) *Plugin {
	p := New(adapter.NewRegistry(), nil)
	p.guardrails = &cachedGuardrailClient{cache: &clientCache{
		build: func(context.Context, awsCredentials) (guardrailClient, error) { return g, nil },
	}}
	return p
}

// A text just under what a quota pacer would have served in a call's budget, in
// the region with the smallest quota, with the harmful part in its LAST chunk.
// A pacer that spaces the chunks out leaves that chunk waiting for the end of
// the budget, so it times out and the request fails open: a client chooses how
// long its last chunk waits by padding. Every chunk is sent at once here, so the
// last one is judged and the request is refused.
func TestAHarmfulLastChunkOfAMessageNearTheOldBoundIsNeverFailedOpen(t *testing.T) {
	t.Parallel()
	text := benignWords(252000) + " HARMFUL-TAIL"
	g := &latencyGuardrail{delay: 500 * time.Millisecond, block: "HARMFUL-TAIL"}
	p := pluginOver(g)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, text), nil)
	in.Event = event

	started := time.Now()
	res, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "the harmful chunk must be judged and refused, got res=%v err=%v after %s", res, err, time.Since(started))
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "blocked", extras.Decision)
	assert.Greater(t, extras.ChunkCount, 8)
	assert.Less(t, time.Since(started), 5*time.Second, "the chunks run in parallel rounds, not spread over the budget")
}

// The chunks after the first round wait for this request's own earlier chunks. A
// chunk that is cut by the evaluation's budget after waiting was kept from
// finishing by the request's size, so it is input, not an outage.
func TestAChunkCutByTheBudgetAfterWaitingIsInputInEnforce(t *testing.T) {
	t.Parallel()
	// The marker sits in the sixth chunk, which waits behind the first four.
	words := benignWords(150000)
	text := words[:125000] + " HANG-HERE " + words[125000:]
	g := &latencyGuardrail{delay: 10 * time.Millisecond, hang: "HANG-HERE"}
	p := pluginOver(g)
	p.budget = 2 * time.Second
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, text), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got res=%v err=%v", res, err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "input", extras.FailureClass)
	assert.Equal(t, appplugins.DetailChunkBudget, extras.FailureDetail)
}

// The provider being slow on a chunk of the first round is its own doing.
func TestASlowChunkOfTheFirstRoundIsAvailability(t *testing.T) {
	t.Parallel()
	text := "HANG-HERE " + benignWords(150000)
	g := &latencyGuardrail{delay: 10 * time.Millisecond, hang: "HANG-HERE"}
	p := pluginOver(g)
	p.budget = time.Second
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, text), nil)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
}
