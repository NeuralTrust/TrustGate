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
	"errors"
	"net/http"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// previewableFake wraps the package's fakePlugin with an explicit opt-in answer,
// so a plugin can be built that implements Previewable and still says no.
type previewableFake struct {
	*fakePlugin
	opted bool
	// modes overrides the shared fake's enforce-only declaration, so the mode check
	// can be exercised from both sides without touching the executor's fixture.
	modes []policy.Mode
}

func (p previewableFake) Previewable() bool { return p.opted }

func (p previewableFake) SupportedModes() []policy.Mode {
	if len(p.modes) > 0 {
		return p.modes
	}
	return p.fakePlugin.SupportedModes()
}

func preRequestFake(name string) *fakePlugin {
	return &fakePlugin{name: name, stages: []policy.Stage{policy.StagePreRequest}, mutReq: true}
}

func previewSvc(t *testing.T, p Plugin) PreviewService {
	t.Helper()
	reg := NewRegistry()
	require.NoError(t, reg.Register(p))
	return NewPreviewService(reg)
}

func TestPreviewRefusesAPluginThatDidNotOptIn(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		plugin Plugin
	}{
		{name: "does not implement Previewable", plugin: preRequestFake("plain")},
		{name: "implements it but answers false", plugin: previewableFake{fakePlugin: preRequestFake("plain"), opted: false}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			svc := previewSvc(t, tt.plugin)

			_, err := svc.Preview(context.Background(), PreviewInput{Slug: "plain", Body: []byte(`{}`)})

			require.Error(t, err)
			assert.ErrorIs(t, err, ErrPluginNotPreviewable)
		})
	}
}

func TestPreviewReportsAnUnknownPluginAsNotFound(t *testing.T) {
	t.Parallel()
	svc := NewPreviewService(NewRegistry())

	_, err := svc.Preview(context.Background(), PreviewInput{Slug: "nope", Body: []byte(`{}`)})

	assert.ErrorIs(t, err, commonerrors.ErrNotFound)
}

func TestPreviewReportsUnacceptableSettingsAsInvalidConfig(t *testing.T) {
	t.Parallel()
	fake := preRequestFake("p")
	fake.validErr = errors.New("bad setting")
	svc := previewSvc(t, previewableFake{fakePlugin: fake, opted: true})

	_, err := svc.Preview(context.Background(), PreviewInput{Slug: "p", Body: []byte(`{}`)})

	assert.ErrorIs(t, err, commonerrors.ErrInvalidConfig)
	assert.Contains(t, err.Error(), "bad setting")
}

func TestPreviewReturnsTheRewrittenBodyAndTheHeadersItRanWith(t *testing.T) {
	t.Parallel()
	rewritten := []byte(`{"messages":[{"role":"system","content":"hi"}]}`)
	var seen ExecInput
	fake := preRequestFake("p")
	fake.execFn = func(in ExecInput) (*Result, error) {
		seen = in
		return &Result{StatusCode: http.StatusOK, RequestBody: rewritten}, nil
	}
	svc := previewSvc(t, previewableFake{fakePlugin: fake, opted: true})

	got, err := svc.Preview(context.Background(), PreviewInput{
		Slug:    "p",
		Body:    []byte(`{"messages":[]}`),
		Headers: map[string][]string{"X-Tenant-Id": {"acme"}},
	})

	require.NoError(t, err)
	assert.Equal(t, PreviewRewritten, got.Decision)
	assert.JSONEq(t, string(rewritten), string(got.RequestBody))
	require.NotNil(t, seen.Request)
	assert.Equal(t, map[string][]string{"X-Tenant-Id": {"acme"}}, seen.Request.Headers)
	assert.Equal(t, policy.ModeEnforce, seen.Mode)
	assert.Equal(t, policy.StagePreRequest, seen.Stage)
}

func TestPreviewEchoesTheSampleWhenThePluginChangesNothing(t *testing.T) {
	t.Parallel()
	sample := []byte(`{"messages":[]}`)
	fake := preRequestFake("p")
	fake.result = &Result{StatusCode: http.StatusOK}
	svc := previewSvc(t, previewableFake{fakePlugin: fake, opted: true})

	got, err := svc.Preview(context.Background(), PreviewInput{Slug: "p", Body: sample})

	require.NoError(t, err)
	assert.Equal(t, PreviewUnchanged, got.Decision)
	assert.Equal(t, sample, got.RequestBody)
}

// A rejection is what the operator asked to see, so it is a successful preview
// rather than an error bubbling out of the endpoint.
func TestPreviewReportsAPluginRejectionAsAnOutcome(t *testing.T) {
	t.Parallel()
	fake := preRequestFake("p")
	fake.err = &PluginError{
		StatusCode: http.StatusBadRequest,
		Type:       "template_variable_unresolved",
		Message:    `context variable "tenant" could not be resolved`,
	}
	svc := previewSvc(t, previewableFake{fakePlugin: fake, opted: true})

	got, err := svc.Preview(context.Background(), PreviewInput{Slug: "p", Body: []byte(`{}`)})

	require.NoError(t, err)
	assert.Equal(t, PreviewRejected, got.Decision)
	assert.Equal(t, http.StatusBadRequest, got.Status)
	assert.Equal(t, "template_variable_unresolved", got.Type)
	assert.Contains(t, got.Message, "tenant")
}

func TestPreviewHonoursTheRequestedMode(t *testing.T) {
	t.Parallel()
	var seen ExecInput
	fake := preRequestFake("p")
	fake.execFn = func(in ExecInput) (*Result, error) {
		seen = in
		return &Result{StatusCode: http.StatusOK}, nil
	}
	svc := previewSvc(t, previewableFake{
		fakePlugin: fake,
		opted:      true,
		modes:      []policy.Mode{policy.ModeEnforce, policy.ModeObserve},
	})

	_, err := svc.Preview(context.Background(), PreviewInput{Slug: "p", Mode: policy.ModeObserve, Body: []byte(`{}`)})

	require.NoError(t, err)
	assert.Equal(t, policy.ModeObserve, seen.Mode)
}

// Previewing a mode the plugin does not support would answer for a policy the create
// path refuses with 422 — a green preview for something that cannot exist.
func TestPreviewRefusesAModeThePluginDoesNotSupport(t *testing.T) {
	t.Parallel()
	fake := preRequestFake("p")
	svc := previewSvc(t, previewableFake{
		fakePlugin: fake,
		opted:      true,
		modes:      []policy.Mode{policy.ModeEnforce},
	})

	_, err := svc.Preview(context.Background(), PreviewInput{Slug: "p", Mode: policy.ModeThrottle, Body: []byte(`{}`)})

	require.Error(t, err)
	assert.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.ErrorIs(t, err, ErrModeNotSupported)
}

// A plugin may block by short-circuiting instead of returning a PluginError;
// reporting that as "unchanged" would tell the operator the opposite of the truth.
func TestPreviewReportsAShortCircuitAsRejected(t *testing.T) {
	t.Parallel()
	fake := preRequestFake("p")
	fake.result = &Result{StatusCode: http.StatusForbidden, StopUpstream: true, Body: []byte("blocked")}
	svc := previewSvc(t, previewableFake{fakePlugin: fake, opted: true})

	got, err := svc.Preview(context.Background(), PreviewInput{Slug: "p", Body: []byte(`{}`)})

	require.NoError(t, err)
	assert.Equal(t, PreviewRejected, got.Decision)
	assert.Equal(t, http.StatusForbidden, got.Status)
	assert.Equal(t, "blocked", got.Message)
}

// errors.Join keeps the plugin's own message reachable instead of flattening it.
func TestPreviewKeepsTheValidationCauseReachable(t *testing.T) {
	t.Parallel()
	cause := errors.New("template_engine \"jinja2\" is not supported")
	fake := preRequestFake("p")
	fake.validErr = cause
	svc := previewSvc(t, previewableFake{fakePlugin: fake, opted: true})

	_, err := svc.Preview(context.Background(), PreviewInput{Slug: "p", Body: []byte(`{}`)})

	assert.ErrorIs(t, err, commonerrors.ErrInvalidConfig)
	assert.ErrorIs(t, err, cause)
}
