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

package plugins

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// localPlugin marks a fakePlugin as a local rewriter (LocalRewriter opt-in).
type localPlugin struct{ *fakePlugin }

func (localPlugin) RewritesLocally() bool { return true }

var preResp = []policy.Stage{policy.StagePreResponse}

func resp(slug string, priority int) polSpec {
	return polSpec{slug: slug, enabled: true, priority: priority, parallel: true, stages: preResp}
}

// RUN-1745: an off-box rewriter (bedrock_guardrail, google_model_armor) that
// sorts before a local one (regex_replace) must still run after it, or the
// third party receives the text the local mask hides from the client.
func TestStagePlan_GroupBatches_LocalRewritersBeforeOffBox(t *testing.T) {
	remote := &fakePlugin{name: "a_remote", stages: preReq, result: &Result{}, mutReq: true}
	remote2 := &fakePlugin{name: "b_remote", stages: preReq, result: &Result{}, mutReq: true}
	local := localPlugin{&fakePlugin{name: "c_local", stages: preReq, result: &Result{}, mutReq: true}}
	read := readerPlugin{&fakePlugin{name: "d_read", stages: preReq, result: &Result{}}}
	neutral := &fakePlugin{name: "e_rate", stages: preReq, result: &Result{}}
	respLocal := localPlugin{&fakePlugin{name: "f_resplocal", stages: preReq, result: &Result{}, mutResp: true}}
	reg := newRegistry(t, remote, remote2, local, read, neutral, respLocal)

	tests := []struct {
		name  string
		specs []polSpec
		want  [][]string
	}{
		{
			name:  "the local rewriter runs first, then the off-box one, then readers",
			specs: []polSpec{pre("a_remote", 0, true), pre("c_local", 0, true), pre("d_read", 0, true)},
			want:  [][]string{{"c_local"}, {"a_remote"}, {"d_read"}},
		},
		{
			name:  "off-box rewriters keep their mutual order",
			specs: []polSpec{pre("a_remote", 0, true), pre("b_remote", 0, true), pre("c_local", 0, true)},
			want:  [][]string{{"c_local"}, {"a_remote"}, {"b_remote"}},
		},
		{
			name:  "a neutral entry keeps its exact place",
			specs: []polSpec{pre("a_remote", 0, true), pre("c_local", 0, true), pre("e_rate", 0, true)},
			want:  [][]string{{"c_local"}, {"a_remote", "e_rate"}},
		},
		{
			name:  "a local rewriter of the other body does not move at a request stage",
			specs: []polSpec{pre("a_remote", 0, true), pre("f_resplocal", 0, true)},
			want:  [][]string{{"a_remote", "f_resplocal"}},
		},
		{
			name:  "different priorities are untouched",
			specs: []polSpec{pre("a_remote", 0, true), pre("c_local", 1, true)},
			want:  [][]string{{"a_remote"}, {"c_local"}},
		},
		{
			name:  "a non-parallel entry is a boundary the reorder never crosses",
			specs: []polSpec{pre("a_remote", 0, true), pre("b_remote", 0, false), pre("c_local", 0, true)},
			want:  [][]string{{"a_remote"}, {"b_remote"}, {"c_local"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			plan := NewStagePlan(reg, policies(t, tt.specs...), nil)
			assert.Equal(t, tt.want, batchSlugs(plan.batchesFor(policy.StagePreRequest)))
		})
	}
}

func TestExecutor_RunStage_OffBoxRewriterSeesTheLocalMask(t *testing.T) {
	var seen atomic.Value
	remote := &fakePlugin{
		name: "a_remote", stages: preReq, mutReq: true,
		execFn: func(in ExecInput) (*Result, error) {
			seen.Store(string(in.Request.Body))
			return &Result{}, nil
		},
	}
	local := localPlugin{&fakePlugin{
		name: "z_local", stages: preReq, mutReq: true,
		result: &Result{RequestBody: []byte("masked")},
	}}
	exec := NewExecutor(newRegistry(t, remote, local), nil)

	req := &infracontext.RequestContext{Body: []byte("original")}
	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreRequest,
		Policies: policies(t, pre("a_remote", 0, true), pre("z_local", 0, true)),
		Request:  req,
		Response: &infracontext.ResponseContext{},
	})
	require.NoError(t, err)
	assert.Equal(t, "masked", seen.Load(), "the off-box rewriter must receive the masked request")
}

// A buffered response rewrite is a short-circuit carrying the new body. It
// must not end the stage: the guards after it, at its priority or a later one,
// judge the rewritten body, and a later rewrite builds on it (RUN-1745).
func TestExecutor_RunStage_PreResponseRewriteIsHandedOn(t *testing.T) {
	var guardSaw atomic.Value
	mask := localPlugin{&fakePlugin{
		name: "a_mask", stages: preResp, mutResp: true,
		execFn: func(in ExecInput) (*Result, error) {
			return &Result{StatusCode: http.StatusOK, Body: []byte(string(in.Response.Body) + " masked"), StopUpstream: true}, nil
		},
	}}
	second := &fakePlugin{
		name: "b_second", stages: preResp, mutResp: true,
		execFn: func(in ExecInput) (*Result, error) {
			return &Result{StatusCode: http.StatusOK, Body: []byte(string(in.Response.Body) + " twice"), StopUpstream: true}, nil
		},
	}
	guard := &fakePlugin{
		name: "c_guard", stages: preResp,
		execFn: func(in ExecInput) (*Result, error) {
			guardSaw.Store(string(in.Response.Body))
			return &Result{}, nil
		},
	}
	exec := NewExecutor(newRegistry(t, mask, second, guard), nil)

	response := &infracontext.ResponseContext{StatusCode: http.StatusOK, Body: []byte("upstream")}
	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreResponse,
		Policies: policies(t, resp("a_mask", 0), resp("b_second", 0), resp("c_guard", 1)),
		Response: response,
	})

	require.NoError(t, err)
	assert.Equal(t, "upstream masked twice", guardSaw.Load(), "a later guard must judge the rewritten body")
	require.True(t, out.ShortCircuit, "the rewrite still ends the response")
	assert.Equal(t, "upstream masked twice", string(out.Body))
	assert.Equal(t, "upstream masked twice", string(response.Body))
}

func TestExecutor_RunStage_PreResponseBlockAfterARewriteStillBlocks(t *testing.T) {
	mask := localPlugin{&fakePlugin{
		name: "a_mask", stages: preResp, mutResp: true,
		result: &Result{StatusCode: http.StatusOK, Body: []byte("masked"), StopUpstream: true},
	}}
	guard := &fakePlugin{
		name: "b_guard", stages: preResp,
		err: &PluginError{StatusCode: http.StatusForbidden, Message: "blocked"},
	}
	exec := NewExecutor(newRegistry(t, mask, guard), nil)

	_, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreResponse,
		Policies: policies(t, resp("a_mask", 0), resp("b_guard", 1)),
		Response: &infracontext.ResponseContext{StatusCode: http.StatusOK, Body: []byte("raw")},
	})

	pe, ok := AsPluginError(err)
	require.True(t, ok, "the guard's block must surface, got %v", err)
	assert.Equal(t, http.StatusForbidden, pe.StatusCode)
}

// A non-2xx short-circuit is a denial (the MCP runner reads it so), never a
// rewrite: nothing after it runs, so nothing can overwrite the block.
func TestExecutor_RunStage_PreResponseDenialStillEndsTheStage(t *testing.T) {
	calls := int32(0)
	deny := &fakePlugin{
		name: "a_deny", stages: preResp, mutResp: true,
		result: &Result{StatusCode: http.StatusForbidden, Body: []byte("denied"), StopUpstream: true},
	}
	after := &fakePlugin{
		name: "b_after", stages: preResp, mutResp: true, calls: &calls,
		result: &Result{StatusCode: http.StatusOK, Body: []byte("rewritten"), StopUpstream: true},
	}
	exec := NewExecutor(newRegistry(t, deny, after), nil)

	out, err := exec.RunStage(context.Background(), StageInput{
		Stage:    policy.StagePreResponse,
		Policies: policies(t, resp("a_deny", 0), resp("b_after", 1)),
		Response: &infracontext.ResponseContext{StatusCode: http.StatusOK, Body: []byte("raw")},
	})

	require.NoError(t, err)
	require.True(t, out.ShortCircuit)
	assert.Equal(t, http.StatusForbidden, out.StatusCode)
	assert.Equal(t, "denied", string(out.Body))
	assert.Zero(t, atomic.LoadInt32(&calls), "nothing may run after a denial")
}
