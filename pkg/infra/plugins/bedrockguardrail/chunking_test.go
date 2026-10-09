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

// waits stands in for the pacer's clock: time does not move and sleeping records
// how long each call would have waited, so a test reads the pacing without
// spending it.
type waits struct {
	mu sync.Mutex
	d  []time.Duration
}

func (w *waits) install(p *Plugin) {
	at := time.Unix(1_700_000_000, 0)
	p.pacer.now = func() time.Time { return at }
	p.pacer.sleep = func(_ context.Context, d time.Duration) error {
		w.mu.Lock()
		w.d = append(w.d, d)
		w.mu.Unlock()
		return nil
	}
}

func (w *waits) longest() time.Duration {
	w.mu.Lock()
	defer w.mu.Unlock()
	var longest time.Duration
	for _, d := range w.d {
		longest = max(longest, d)
	}
	return longest
}

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

func TestALongMessageInASmallQuotaRegionIsSentInPacedChunks(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)
	clock := &waits{}
	clock.install(p)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, benignWords(100000)), nil)
	event, span := eventFor(t)
	in.Event = event

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	require.GreaterOrEqual(t, len(g.inputs), 5)
	units := 0
	for _, text := range g.inputs {
		assert.LessOrEqual(t, len(text), chunkBytes)
		units += textUnits(len(text))
	}
	wait := clock.longest()
	assert.Greater(t, wait, (time.Duration(units-25)*time.Second/25)-time.Second, "the units above the first burst of 25 wait for the quota's 25 a second")
	assert.Less(t, wait, 10*time.Second)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, len(g.inputs), extras.ChunkCount)
	assert.Equal(t, "allowed", extras.Decision)
}

func TestTheLargestUSRegionsAreNotPacedForAMessageTheirBurstServes(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)
	clock := &waits{}
	clock.install(p)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, benignWords(100000)), nil)

	res, err := p.Execute(context.Background(), in)

	assertPassThrough(t, res, err)
	assert.Zero(t, clock.longest(), "105 text units fit the 200-unit burst")
}

func TestAMessageOfThirtyThreeChunksIsRefusedBeforeAnyCall(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, benignWords(33*chunkBytes)), nil)

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
	text := "BLOCKME " + benignWords(280000)
	for _, tc := range []struct {
		mode    policy.Mode
		decided string
	}{{policy.ModeEnforce, "blocked"}, {policy.ModeObserve, "reported"}} {
		t.Run(string(tc.mode), func(t *testing.T) {
			t.Parallel()
			g := blockOnMarker("BLOCKME")
			p := streamPlugin(t, g)
			(&waits{}).install(p)
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
	(&waits{}).install(p)
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
	(&waits{}).install(p)
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
	(&waits{}).install(p)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("us-east-1"), chatRequestOf(t, benignWords(150000)), nil)
	in.Event = event

	_, err := p.Execute(context.Background(), in)

	pe, ok := appplugins.AsPluginError(err)
	require.True(t, ok, "got %v", err)
	assert.Equal(t, appplugins.TypeGuardrailInputUninspectable, pe.Type)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, appplugins.DetailCoveragePartial, extras.FailureDetail)
}

// The quota held by other traffic for longer than the call can wait is
// availability: the request's own calls never exceeded the floor.
func TestAQuotaHeldByOtherTrafficFailsOpenAsThrottled(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)
	creds := credsOf(t, settingsIn("eu-west-3"))
	now := time.Unix(1_700_000_000, 0)
	p.pacer.now = func() time.Time { return now }
	drain(p, creds, now)
	event, span := eventFor(t)
	in := execInput(policy.StagePreRequest, policy.ModeEnforce, settingsIn("eu-west-3"), chatRequestOf(t, benignWords(60000)), nil)
	in.Event = event

	res, err := p.Execute(ctxWithDeadline(t, 2*time.Second), in)

	assertPassThrough(t, res, err)
	assert.Zero(t, g.calls)
	extras, ok := span.PluginAttrsCopy().Extras.(*Data)
	require.True(t, ok)
	assert.Equal(t, "availability", extras.FailureClass)
	assert.Equal(t, appplugins.DetailThrottled, extras.FailureDetail)
	assert.Equal(t, appplugins.DecisionFailedOpen, extras.Decision)
}

// drain spends the credential's quota for minutes ahead, as other traffic on the
// account would.
func drain(p *Plugin, creds awsCredentials, now time.Time) {
	for i := 0; i < 600; i++ {
		p.pacer.limiter(creds).ReserveN(now, 25)
	}
}

func credsOf(t *testing.T, settings map[string]any) awsCredentials {
	t.Helper()
	cfg, err := parseConfig(settings)
	require.NoError(t, err)
	return credentialsFromConfig(cfg.Credentials)
}

func ctxWithDeadline(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

func TestTheStreamLegSpendsTheSameQuota(t *testing.T) {
	t.Parallel()
	g := allowing()
	p := streamPlugin(t, g)
	creds := credsOf(t, streamSettings(nil))
	now := time.Unix(1_700_000_000, 0)
	p.pacer.now = func() time.Time { return now }
	drain(p, creds, now)

	verdict, err := p.InspectSegment(context.Background(), streamInput(policy.ModeEnforce, streamSettings(nil), nil), segment(1, "a streamed block"))

	assert.Nil(t, verdict)
	var failure *appplugins.ExternalStreamFailure
	require.ErrorAs(t, err, &failure)
	assert.Equal(t, appplugins.DetailThrottled, failure.Detail)
	assert.Equal(t, appplugins.FailureClassAvailability, failure.Class)
	assert.Zero(t, g.calls)
}

func TestThePacerGivesBackTheReservationItCannotWaitFor(t *testing.T) {
	t.Parallel()
	creds := awsCredentials{region: "eu-west-3", accessKeyID: "AKIA", secretAccessKey: "s"}
	now := time.Unix(1_700_000_000, 0)
	p := &pacer{now: func() time.Time { return now }}
	require.NoError(t, p.Wait(context.Background(), creds, 25))

	err := p.Wait(ctxWithDeadline(t, 100*time.Millisecond), creds, 25)
	require.ErrorIs(t, err, errPacerSaturated)
	p.sleep = func(context.Context, time.Duration) error { return nil }
	require.NoError(t, p.Wait(context.Background(), creds, 25), "the refused reservation was returned, so one second is enough")
}

func TestRegionFloors(t *testing.T) {
	t.Parallel()
	assert.Equal(t, regionQuota{50, 200}, floorFor("us-east-1"))
	assert.Equal(t, regionQuota{50, 200}, floorFor("us-west-2"))
	assert.Equal(t, regionQuota{25, 25}, floorFor("eu-west-3"))
	assert.Equal(t, regionQuota{50, 200}, floorFor(""))
	assert.Equal(t, 275, demandBound(floorFor("eu-south-1")))
	assert.Equal(t, 700, demandBound(floorFor("us-east-1")))
	assert.Equal(t, 24, textUnits(chunkBytes))
	assert.Equal(t, 1, textUnits(1))
	assert.Equal(t, 0, textUnits(0))
}
