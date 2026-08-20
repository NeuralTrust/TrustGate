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

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"runtime"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// stubDataFinder answers with a fixed consumer view, so a test can express
// "the world changed between two passes" as a different value.
type stubDataFinder struct {
	data *appconsumer.Data
	err  error
}

func (f *stubDataFinder) FindByGateway(context.Context, ids.GatewayID) (*appconsumer.Data, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.data, nil
}

// passthroughScoper stands in for the inline-consumer path, where role scoping is
// the identity function.
type passthroughScoper struct{ err error }

func (s passthroughScoper) Scope(
	_ context.Context,
	rc *appconsumer.RoutableConsumer,
	_ *appconsumer.Data,
) (*appconsumer.RoutableConsumer, error) {
	if s.err != nil {
		return nil, s.err
	}
	return rc, nil
}

type denyingDiscoveryExecutor struct{}

func (denyingDiscoveryExecutor) RunStage(
	context.Context,
	appplugins.StageInput,
) (*appplugins.StageOutcome, error) {
	return nil, &appplugins.PluginError{StatusCode: 403, Message: "blocked"}
}

type recordingDiscoveryExecutor struct {
	body []byte
}

func (e *recordingDiscoveryExecutor) RunStage(
	_ context.Context,
	input appplugins.StageInput,
) (*appplugins.StageOutcome, error) {
	e.body = append([]byte(nil), input.Response.Body...)
	return &appplugins.StageOutcome{}, nil
}

type gatedPolicyFinder struct {
	data    *appconsumer.Data
	started chan struct{}
	release chan struct{}
	calls   atomic.Int64
}

func (f *gatedPolicyFinder) FindByGateway(ctx context.Context, _ ids.GatewayID) (*appconsumer.Data, error) {
	f.calls.Add(1)
	f.started <- struct{}{}
	select {
	case <-f.release:
		return f.data, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

const policyTestSlug = "acme"

func policyConsumer(t *testing.T, authID ids.AuthID, regs ...*registrydomain.Registry) *consumerdomain.Consumer {
	t.Helper()
	registryIDs := make([]ids.RegistryID, 0, len(regs))
	for _, reg := range regs {
		registryIDs = append(registryIDs, reg.ID)
	}
	return &consumerdomain.Consumer{
		ID:          ids.New[ids.ConsumerKind](),
		Type:        consumerdomain.TypeMCP,
		Slug:        policyTestSlug,
		Active:      true,
		AuthIDs:     []ids.AuthID{authID},
		RegistryIDs: registryIDs,
	}
}

func policyData(consumer *consumerdomain.Consumer, regs ...*registrydomain.Registry) *appconsumer.Data {
	return appconsumer.NewData(ids.New[ids.GatewayKind](), []appconsumer.RoutableConsumer{
		{Consumer: consumer, Registries: regs},
	})
}

// policyIdentity derives the lease identity the handler would have captured for
// this consumer view, so a later drift in the view is a real drift.
func policyIdentity(
	authID ids.AuthID,
	data *appconsumer.Data,
	honoured ...NotificationKind,
) LeaseIdentity {
	rc, _ := data.MatchPath(appconsumer.MCPPath(policyTestSlug))
	return LeaseIdentity{
		Key:       IsolationKey{RoleScope: SurfaceConfigFingerprint(rc)},
		GatewayID: data.GatewayID,
		AuthID:    authID,
		Path:      appconsumer.MCPPath(policyTestSlug),
		Honoured:  NewHonouredSet(honoured...),
	}
}

func TestSubscriptionPolicyDigestFiltersAppsListsBeforePlugins(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"
	reg := mcpRegistry(t, "github", url)
	validTool := mustAppsTool(t, `{"name":"app","_meta":{"ui":{"resourceUri":"ui://widget/app"}}}`)
	plainTool := mustAppsTool(t, `{"name":"plain","_meta":{"trace":1}}`)
	validResource := mustAppsResource(t, `{"name":"app","uri":"ui://widget/app","_meta":{"ui":{}}}`)
	plainResource := mustAppsResource(t, `{"name":"plain","uri":"https://example.com","_meta":{"trace":1}}`)
	templates := []ResourceTemplate{{Name: "template", URITemplate: "doc://{id}"}}
	composer := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{
		url: {
			tools: []Tool{mustAppsTool(t, `{"name":"invalid","_meta":{"ui":"bad"}}`), validTool, plainTool},
			resources: []Resource{
				mustAppsResource(t, `{"name":"invalid","uri":"https://example.com","_meta":{"ui":{}}}`), validResource, plainResource,
			},
			templates: templates,
		},
	}})
	metadata, err := NewAppsMetadataPolicy(2, 2, nil, nil)
	if err != nil {
		t.Fatalf("build metadata policy: %v", err)
	}
	recorder := &recordingDiscoveryExecutor{}
	policy := NewSubscriptionPolicyWithAppsListPolicy(nil, nil, composer,
		NewAppsListPolicy(true, metadata), NewPluginRunner(recorder, nil)).(*subscriptionPolicy)
	rc := routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg)

	toolsDigest, err := policy.digest(context.Background(), rc, NotificationToolsListChanged)
	if err != nil {
		t.Fatalf("digest tools: %v", err)
	}
	filteredTools := []Tool{validTool, plainTool}
	encodedTools, _ := encodeSurface(filteredTools, func(tool Tool) string { return tool.Name })
	pluginBody, _ := json.Marshal(map[string]any{"tools": filteredTools})
	if toolsDigest != digestOf(encodedTools) || string(recorder.body) != string(pluginBody) {
		t.Fatalf("tools digest/plugin input retained invalid Apps metadata: digest=%q body=%s", toolsDigest, recorder.body)
	}

	resourcesDigest, err := policy.digest(context.Background(), rc, NotificationResourcesListChanged)
	if err != nil {
		t.Fatalf("digest resources: %v", err)
	}
	encodedResources, _ := encodeSurface([]Resource{validResource, plainResource}, func(resource Resource) string {
		return resource.Name + "\x00" + resource.URI
	})
	encodedTemplates, _ := encodeSurface(templates, func(template ResourceTemplate) string {
		return template.Name + "\x00" + template.URITemplate
	})
	if resourcesDigest != digestOf(encodedResources, encodedTemplates) {
		t.Fatalf("resources digest retained invalid Apps metadata: %q", resourcesDigest)
	}
}

func TestSubscriptionPolicyDigestDropsAppsWhenResourcesFail(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"
	reg := mcpRegistry(t, "github", url)
	plain := mustAppsTool(t, `{"name":"plain"}`)
	composer := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{url: {
		tools: []Tool{
			plain,
			mustAppsTool(t, `{"name":"app","_meta":{"ui":{"resourceUri":"ui://widget/app"}}}`),
		},
		resourcesErr: errors.New("resource discovery failed"),
	}}})
	metadata, err := NewAppsMetadataPolicy(1, 1, nil, nil)
	if err != nil {
		t.Fatalf("build metadata policy: %v", err)
	}
	recorder := &recordingDiscoveryExecutor{}
	policy := NewSubscriptionPolicyWithAppsListPolicy(nil, nil, composer,
		NewAppsListPolicy(true, metadata), NewPluginRunner(recorder, nil)).(*subscriptionPolicy)

	digest, err := policy.digest(context.Background(),
		routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg), NotificationToolsListChanged)
	encoded, _ := encodeSurface([]Tool{plain}, func(tool Tool) string { return tool.Name })
	if err != nil || digest != digestOf(encoded) {
		t.Fatalf("digest = %q, err = %v", digest, err)
	}
}

func TestSubscriptionPolicyLegacyConstructorsDisableAppsFiltering(t *testing.T) {
	t.Parallel()
	constructors := map[string]func(Composer, *PluginRunner) *subscriptionPolicy{
		"default": func(c Composer, p *PluginRunner) *subscriptionPolicy {
			return NewSubscriptionPolicy(nil, nil, c, p).(*subscriptionPolicy)
		},
		"upstream": func(c Composer, p *PluginRunner) *subscriptionPolicy {
			return NewSubscriptionPolicyWithUpstream(nil, nil, c, p, nil, nil).(*subscriptionPolicy)
		},
	}
	for name, construct := range constructors {
		t.Run(name, func(t *testing.T) {
			const url = "https://a.example.com/mcp"
			reg := mcpRegistry(t, "github", url)
			invalid := mustAppsTool(t, `{"name":"legacy","_meta":{"ui":"bad"}}`)
			composer := newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{
				url: {tools: []Tool{invalid}},
			}})
			recorder := &recordingDiscoveryExecutor{}
			policy := construct(composer, NewPluginRunner(recorder, nil))
			digest, err := policy.digest(context.Background(),
				routable(&consumerdomain.Consumer{Type: consumerdomain.TypeMCP}, reg), NotificationToolsListChanged)
			if err != nil {
				t.Fatalf("digest tools: %v", err)
			}
			encoded, _ := encodeSurface([]Tool{invalid}, func(tool Tool) string { return tool.Name })
			body, _ := json.Marshal(map[string]any{"tools": []Tool{invalid}})
			if digest != digestOf(encoded) || string(recorder.body) != string(body) {
				t.Fatalf("legacy constructor filtered Apps metadata: digest=%q body=%s", digest, recorder.body)
			}
		})
	}
}

func TestSubscriptionPolicy_Evaluate_RefusalTerminatesRatherThanNarrows(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"

	tests := []struct {
		name string
		// mutate rewrites the world the second pass resolves.
		mutate func(t *testing.T, consumer *consumerdomain.Consumer, reg *registrydomain.Registry) *appconsumer.Data
		scoper RoleScoper
	}{
		{
			name: "the path no longer resolves to a virtual MCP",
			mutate: func(_ *testing.T, consumer *consumerdomain.Consumer, reg *registrydomain.Registry) *appconsumer.Data {
				renamed := *consumer
				renamed.Slug = "somewhere-else"
				return policyData(&renamed, reg)
			},
		},
		{
			name: "the consumer is no longer an MCP consumer",
			mutate: func(_ *testing.T, consumer *consumerdomain.Consumer, reg *registrydomain.Registry) *appconsumer.Data {
				retyped := *consumer
				retyped.Type = consumerdomain.TypeLLM
				return policyData(&retyped, reg)
			},
		},
		{
			name: "the credential is no longer allowed for the consumer",
			mutate: func(_ *testing.T, consumer *consumerdomain.Consumer, reg *registrydomain.Registry) *appconsumer.Data {
				rotated := *consumer
				rotated.AuthIDs = []ids.AuthID{ids.New[ids.AuthKind]()}
				return policyData(&rotated, reg)
			},
		},
		{
			name: "the consumer now accepts the legacy protocol only",
			mutate: func(_ *testing.T, consumer *consumerdomain.Consumer, reg *registrydomain.Registry) *appconsumer.Data {
				legacy := *consumer
				legacy.MCP = &consumerdomain.MCPPolicy{
					ProtocolAcceptance: consumerdomain.ProtocolAcceptanceLegacyOnly,
				}
				return policyData(&legacy, reg)
			},
		},
		{
			name: "the principal lost its role grant",
			mutate: func(_ *testing.T, consumer *consumerdomain.Consumer, reg *registrydomain.Registry) *appconsumer.Data {
				return policyData(consumer, reg)
			},
			scoper: passthroughScoper{err: ErrNoRoleAccess},
		},
		{
			name: "the registry was detached",
			mutate: func(t *testing.T, consumer *consumerdomain.Consumer, _ *registrydomain.Registry) *appconsumer.Data {
				other := mcpRegistry(t, "other", "https://b.example.com/mcp")
				detached := *consumer
				detached.RegistryIDs = []ids.RegistryID{other.ID}
				return policyData(&detached, other)
			},
		},
		{
			name: "the toolkit no longer exposes the kind",
			mutate: func(_ *testing.T, consumer *consumerdomain.Consumer, reg *registrydomain.Registry) *appconsumer.Data {
				narrowed := *consumer
				narrowed.MCP = &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
					{RegistryID: reg.ID, Prompt: consumerdomain.ToolWildcard},
				}}
				return policyData(&narrowed, reg)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := mcpRegistry(t, "github", url)
			authID := ids.New[ids.AuthKind]()
			consumer := policyConsumer(t, authID, reg)
			opened := policyData(consumer, reg)
			identity := policyIdentity(authID, opened, NotificationToolsListChanged)

			scoper := tc.scoper
			if scoper == nil {
				scoper = passthroughScoper{}
			}
			dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{
				url: {tools: tools("create_issue")},
			}}
			policy := NewSubscriptionPolicy(
				&stubDataFinder{data: tc.mutate(t, consumer, reg)},
				scoper,
				newTestComposer(dialer),
			)

			evaluation, err := policy.Evaluate(context.Background(), identity, SurfaceSnapshot{Tools: "abc"})

			if !errors.Is(err, ErrSubscriptionRevoked) {
				t.Fatalf("error = %v, want %v", err, ErrSubscriptionRevoked)
			}
			if len(evaluation.Changed) != 0 {
				t.Fatalf("a revoked pass emits nothing, got %v", evaluation.Changed)
			}
		})
	}
}

func TestSubscriptionPolicy_Evaluate_ToolsPluginDenialRevokes(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"
	reg := mcpRegistry(t, "github", url)
	authID := ids.New[ids.AuthKind]()
	consumer := policyConsumer(t, authID, reg)
	data := policyData(consumer, reg)
	identity := policyIdentity(authID, data, NotificationToolsListChanged)
	policy := NewSubscriptionPolicy(
		&stubDataFinder{data: data},
		passthroughScoper{},
		newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{
			url: {tools: tools("blocked")},
		}}),
		NewPluginRunner(denyingDiscoveryExecutor{}, nil),
	)

	evaluation, err := policy.Evaluate(context.Background(), identity, SurfaceSnapshot{Tools: "previous"})

	if !errors.Is(err, ErrSubscriptionRevoked) {
		t.Fatalf("error = %v, want %v", err, ErrSubscriptionRevoked)
	}
	if len(evaluation.Changed) != 0 {
		t.Fatalf("a plugin denial must emit nothing, got %v", evaluation.Changed)
	}
}

func TestSubscriptionPolicy_Evaluate_CoalescesEquivalentSnapshots(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"
	reg := mcpRegistry(t, "github", url)
	authID := ids.New[ids.AuthKind]()
	consumer := policyConsumer(t, authID, reg)
	data := policyData(consumer, reg)
	identity := policyIdentity(authID, data, NotificationToolsListChanged)
	identity.Key.ConsumerID = consumer.ID.String()
	identity.Key.Principal = "principal"
	finder := &gatedPolicyFinder{
		data:    data,
		started: make(chan struct{}, 2),
		release: make(chan struct{}),
	}
	policy := NewSubscriptionPolicy(
		finder,
		passthroughScoper{},
		newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{
			url: {tools: tools("search")},
		}}),
	).(*subscriptionPolicy)

	type answer struct {
		evaluation Evaluation
		err        error
	}
	first := make(chan answer, 1)
	second := make(chan answer, 1)
	go func() {
		evaluation, err := policy.Evaluate(context.Background(), identity, SurfaceSnapshot{})
		first <- answer{evaluation: evaluation, err: err}
	}()
	<-finder.started
	go func() {
		evaluation, err := policy.Evaluate(
			context.Background(),
			identity,
			SurfaceSnapshot{Tools: "different"},
		)
		second <- answer{evaluation: evaluation, err: err}
	}()
	waitForFlightWaiters(t, policy, reauthKey(identity), 2)
	close(finder.release)

	firstAnswer := <-first
	secondAnswer := <-second
	if firstAnswer.err != nil || secondAnswer.err != nil {
		t.Fatalf("evaluations failed: first=%v second=%v", firstAnswer.err, secondAnswer.err)
	}
	if finder.calls.Load() != 1 {
		t.Fatalf("compose prologue calls = %d, want 1", finder.calls.Load())
	}
	if len(firstAnswer.evaluation.Changed) != 0 {
		t.Fatalf("first lease changed = %v, want baseline", firstAnswer.evaluation.Changed)
	}
	if !slices.Equal(secondAnswer.evaluation.Changed, []NotificationKind{NotificationToolsListChanged}) {
		t.Fatalf("second lease changed = %v, want tools", secondAnswer.evaluation.Changed)
	}
}

func TestSubscriptionPolicy_Evaluate_DoesNotCoalesceAcrossAuthorizationBoundaries(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"
	reg := mcpRegistry(t, "github", url)
	authID := ids.New[ids.AuthKind]()
	consumer := policyConsumer(t, authID, reg)
	data := policyData(consumer, reg)
	base := policyIdentity(authID, data, NotificationToolsListChanged)
	base.Key.ConsumerID = consumer.ID.String()
	base.Key.Principal = "principal"

	tests := []struct {
		name   string
		mutate func(*LeaseIdentity)
	}{
		{name: "gateway", mutate: func(id *LeaseIdentity) { id.GatewayID = ids.New[ids.GatewayKind]() }},
		{name: "consumer", mutate: func(id *LeaseIdentity) { id.Key.ConsumerID = "other-consumer" }},
		{name: "principal", mutate: func(id *LeaseIdentity) { id.Key.Principal = "other-principal" }},
		{name: "auth id", mutate: func(id *LeaseIdentity) { id.AuthID = ids.New[ids.AuthKind]() }},
		{name: "role scope", mutate: func(id *LeaseIdentity) { id.Key.RoleScope = "other-scope" }},
		{name: "path", mutate: func(id *LeaseIdentity) { id.Path = "/other/mcp" }},
		{
			name: "honoured kinds",
			mutate: func(id *LeaseIdentity) {
				id.Honoured = NewHonouredSet(NotificationPromptsListChanged)
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			finder := &gatedPolicyFinder{
				data:    data,
				started: make(chan struct{}, 2),
				release: make(chan struct{}),
			}
			policy := NewSubscriptionPolicy(
				finder,
				passthroughScoper{},
				newTestComposer(&fakeDialer{upstreams: map[string]*fakeUpstream{
					url: {tools: tools("search"), prompts: []Prompt{}},
				}}),
			)
			other := base
			tc.mutate(&other)
			done := make(chan struct{}, 2)
			go func() {
				_, _ = policy.Evaluate(context.Background(), base, SurfaceSnapshot{})
				done <- struct{}{}
			}()
			go func() {
				_, _ = policy.Evaluate(context.Background(), other, SurfaceSnapshot{})
				done <- struct{}{}
			}()

			awaitFinderStarts(t, finder.started, 2)
			close(finder.release)
			<-done
			<-done
			if finder.calls.Load() != 2 {
				t.Fatalf("compose prologue calls = %d, want 2", finder.calls.Load())
			}
		})
	}
}

// A pass that could not reach the whole surface is inconclusive, not a
// revocation: narrowing a lease on a transient failure is exactly the silent
// narrowing the spec forbids.
func TestSubscriptionPolicy_Evaluate_InconclusivePassKeepsThePreviousSnapshot(t *testing.T) {
	t.Parallel()
	const (
		healthyURL = "https://healthy.example.com/mcp"
		brokenURL  = "https://broken.example.com/mcp"
	)
	previous := SurfaceSnapshot{Tools: "aaaaaaaaaaaa", Prompts: "bbbbbbbbbbbb"}

	tests := []struct {
		name     string
		finder   *stubDataFinder
		failMode consumerdomain.FailMode
		dialErr  error
	}{
		{
			name:   "the consumer data could not be resolved",
			finder: &stubDataFinder{err: errors.New("database unavailable")},
		},
		{
			name:    "a fail-open composition skipped an unreachable registry",
			dialErr: errors.New("connection refused"),
		},
		{
			name:     "a fail-closed composition refused outright",
			failMode: consumerdomain.FailModeClosed,
			dialErr:  errors.New("connection refused"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			healthy := mcpRegistry(t, "healthy", healthyURL)
			broken := mcpRegistry(t, "broken", brokenURL)
			authID := ids.New[ids.AuthKind]()
			consumer := policyConsumer(t, authID, healthy, broken)
			if tc.failMode != "" {
				consumer.MCP = &consumerdomain.MCPPolicy{FailMode: tc.failMode}
			}
			data := policyData(consumer, healthy, broken)
			identity := policyIdentity(authID, data, NotificationToolsListChanged, NotificationPromptsListChanged)

			finder := tc.finder
			if finder == nil {
				finder = &stubDataFinder{data: data}
			}
			dialer := &fakeDialer{
				upstreams: map[string]*fakeUpstream{
					healthyURL: {tools: tools("create_issue"), prompts: []Prompt{}},
					brokenURL:  {tools: tools("list_repos")},
				},
				dialErr: map[string]error{},
			}
			if tc.dialErr != nil {
				dialer.dialErr[brokenURL] = tc.dialErr
			}
			policy := NewSubscriptionPolicy(finder, passthroughScoper{}, newTestComposer(dialer))

			evaluation, err := policy.Evaluate(context.Background(), identity, previous)

			if errors.Is(err, ErrSubscriptionRevoked) {
				t.Fatalf("an inconclusive pass is not a revocation: %v", err)
			}
			if len(evaluation.Changed) != 0 {
				t.Fatalf("an inconclusive pass emits nothing, got %v", evaluation.Changed)
			}
			if evaluation.Snapshot.Tools != previous.Tools ||
				evaluation.Snapshot.Prompts != previous.Prompts ||
				evaluation.Snapshot.Resources != previous.Resources {
				t.Fatalf("snapshot = %+v, want previous digest values %+v", evaluation.Snapshot, previous)
			}
			if err == nil && !evaluation.Snapshot.Degraded {
				t.Fatal("an inconclusive snapshot must be marked degraded")
			}
			if err != nil && evaluation.Snapshot.Degraded {
				t.Fatal("a failed evaluation must return the previous snapshot unchanged")
			}
		})
	}
}

func TestSubscriptionPolicy_Evaluate_EmitsOnlyForKindsWhoseSurfaceMoved(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"

	tests := []struct {
		name    string
		change  func(up *fakeUpstream)
		want    []NotificationKind
		wantNew bool
	}{
		{
			name:   "an unchanged surface emits nothing",
			change: func(*fakeUpstream) {},
		},
		{
			name:    "an added tool emits the tools kind",
			change:  func(up *fakeUpstream) { up.tools = tools("create_issue", "list_repos") },
			want:    []NotificationKind{NotificationToolsListChanged},
			wantNew: true,
		},
		{
			name:    "a removed tool emits the tools kind",
			change:  func(up *fakeUpstream) { up.tools = nil },
			want:    []NotificationKind{NotificationToolsListChanged},
			wantNew: true,
		},
		{
			name:    "a renamed tool emits the tools kind",
			change:  func(up *fakeUpstream) { up.tools = tools("open_issue") },
			want:    []NotificationKind{NotificationToolsListChanged},
			wantNew: true,
		},
		{
			name:    "a changed resource template emits the resources kind",
			change:  func(up *fakeUpstream) { up.templates = []ResourceTemplate{{URITemplate: "doc://{id}"}} },
			want:    []NotificationKind{NotificationResourcesListChanged},
			wantNew: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reg := mcpRegistry(t, "github", url)
			authID := ids.New[ids.AuthKind]()
			consumer := policyConsumer(t, authID, reg)
			data := policyData(consumer, reg)
			identity := policyIdentity(authID, data,
				NotificationToolsListChanged, NotificationResourcesListChanged)

			upstream := &fakeUpstream{
				tools:     tools("create_issue"),
				resources: []Resource{{URI: "doc://one"}},
			}
			// A fresh discovery cache per pass is what an expired TTL looks like
			// to the policy; without it the second compose would answer from the
			// first one's cache and no change could ever be observed.
			finder := &stubDataFinder{data: data}
			dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{url: upstream}}
			first := NewSubscriptionPolicy(finder, passthroughScoper{}, newTestComposer(dialer))

			baseline, err := first.Evaluate(context.Background(), identity, SurfaceSnapshot{})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(baseline.Changed) != 0 {
				t.Fatalf("the first pass establishes a baseline, got %v", baseline.Changed)
			}
			if baseline.Snapshot.Tools == "" || baseline.Snapshot.Resources == "" {
				t.Fatalf("the baseline must digest every honoured kind, got %+v", baseline.Snapshot)
			}

			tc.change(upstream)
			second := NewSubscriptionPolicy(finder, passthroughScoper{}, newTestComposer(dialer))
			evaluation, err := second.Evaluate(context.Background(), identity, baseline.Snapshot)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !slices.Equal(evaluation.Changed, tc.want) {
				t.Fatalf("changed = %v, want %v", evaluation.Changed, tc.want)
			}
			if changed := evaluation.Snapshot != baseline.Snapshot; changed != tc.wantNew {
				t.Fatalf("snapshot moved = %v, want %v", changed, tc.wantNew)
			}
		})
	}
}

// A kind the lease does not honour is never composed and never reported, however
// much the surface behind it moves.
func TestSubscriptionPolicy_Evaluate_NonHonouredKindsAreNeverEmitted(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"
	reg := mcpRegistry(t, "github", url)
	authID := ids.New[ids.AuthKind]()
	consumer := policyConsumer(t, authID, reg)
	data := policyData(consumer, reg)
	identity := policyIdentity(authID, data, NotificationPromptsListChanged)

	upstream := &fakeUpstream{tools: tools("create_issue"), prompts: []Prompt{}}
	dialer := &fakeDialer{upstreams: map[string]*fakeUpstream{url: upstream}}
	finder := &stubDataFinder{data: data}

	baseline, err := NewSubscriptionPolicy(finder, passthroughScoper{}, newTestComposer(dialer)).
		Evaluate(context.Background(), identity, SurfaceSnapshot{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	upstream.tools = tools("create_issue", "list_repos")

	evaluation, err := NewSubscriptionPolicy(finder, passthroughScoper{}, newTestComposer(dialer)).
		Evaluate(context.Background(), identity, baseline.Snapshot)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(evaluation.Changed) != 0 {
		t.Fatalf("changed = %v, want none", evaluation.Changed)
	}
	if evaluation.Snapshot.Tools != "" {
		t.Fatalf("tools digest = %q, want empty for an unhonoured kind", evaluation.Snapshot.Tools)
	}
}

func TestSubscriptionPolicyAuthorizeEventCompleteBinding(t *testing.T) {
	t.Parallel()
	const url = "https://a.example.com/mcp"
	registry := mcpRegistry(t, "github", url)
	authID := ids.New[ids.AuthKind]()
	consumer := policyConsumer(t, authID, registry)
	data := policyData(consumer, registry)
	ctx := appconsumer.WithAuthID(context.Background(), authID)
	requests, err := NewSubscriptionTargetResolver(
		&stubDataFinder{data: data},
		passthroughScoper{},
		nil,
	).Resolve(ctx, data.GatewayID, appconsumer.MCPPath(policyTestSlug), allSubscriptionKinds())
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if len(requests) != 1 {
		t.Fatalf("resolved requests = %d, want 1", len(requests))
	}
	key := multiplexerTestKey("policy-event")
	connector := connectorForPreparedKey(key)

	tests := []struct {
		name       string
		mutateData func(*appconsumer.Data)
		mutateID   func(*SubscriptionIdentity)
		mutateKey  func(*SubscriptionSourceKey)
		kind       NotificationKind
		wantErr    error
		wantOK     bool
	}{
		{name: "unchanged", kind: NotificationToolsListChanged, wantOK: true},
		{
			name: "gateway",
			mutateData: func(current *appconsumer.Data) {
				current.GatewayID = ids.New[ids.GatewayKind]()
			},
			kind:    NotificationToolsListChanged,
			wantErr: ErrSubscriptionRevoked,
		},
		{
			name:     "consumer",
			mutateID: func(identity *SubscriptionIdentity) { identity.ConsumerID = ids.New[ids.ConsumerKind]().String() },
			kind:     NotificationToolsListChanged,
			wantErr:  ErrSubscriptionRevoked,
		},
		{
			name:     "principal",
			mutateID: func(identity *SubscriptionIdentity) { identity.PrincipalFingerprint = "other-principal" },
			kind:     NotificationToolsListChanged,
			wantErr:  ErrSubscriptionRevoked,
		},
		{
			name:     "auth id",
			mutateID: func(identity *SubscriptionIdentity) { identity.AuthID = ids.New[ids.AuthKind]().String() },
			kind:     NotificationToolsListChanged,
			wantErr:  ErrSubscriptionRevoked,
		},
		{
			name:     "registry",
			mutateID: func(identity *SubscriptionIdentity) { identity.RegistryID = ids.New[ids.RegistryKind]().String() },
			kind:     NotificationToolsListChanged,
			wantErr:  ErrSubscriptionRevoked,
		},
		{
			name:     "role scope",
			mutateID: func(identity *SubscriptionIdentity) { identity.RoleScopeFingerprint = "other-role" },
			kind:     NotificationToolsListChanged,
			wantErr:  ErrSubscriptionRevoked,
		},
		{
			name: "detached registry",
			mutateData: func(current *appconsumer.Data) {
				current.Consumers[0].Registries = nil
			},
			kind:    NotificationToolsListChanged,
			wantErr: ErrSubscriptionRevoked,
		},
		{
			name: "denied kind",
			mutateData: func(current *appconsumer.Data) {
				current.Consumers[0].Consumer.MCP = &consumerdomain.MCPPolicy{Toolkit: consumerdomain.Toolkit{
					{RegistryID: registry.ID, Prompt: consumerdomain.ToolWildcard},
				}}
			},
			kind:    NotificationToolsListChanged,
			wantErr: ErrSubscriptionRevoked,
		},
		{
			name: "target",
			mutateKey: func(source *SubscriptionSourceKey) {
				source.TargetDigest = multiplexerDigest("different-target")
			},
			kind:    NotificationToolsListChanged,
			wantErr: ErrSubscriptionSourceChanged,
		},
		{
			name: "credential",
			mutateKey: func(source *SubscriptionSourceKey) {
				source.CredentialFingerprint = multiplexerDigest("different-credential")
			},
			kind:    NotificationToolsListChanged,
			wantErr: ErrSubscriptionSourceChanged,
		},
		{
			name: "protocol",
			mutateKey: func(source *SubscriptionSourceKey) {
				source.ProtocolVersion = "different-protocol"
			},
			kind:    NotificationToolsListChanged,
			wantErr: ErrSubscriptionSourceChanged,
		},
		{
			name: "capability trio",
			mutateKey: func(source *SubscriptionSourceKey) {
				source.Capabilities = ListChangedCapabilities{Tools: true}
			},
			kind:    NotificationToolsListChanged,
			wantErr: ErrSubscriptionSourceChanged,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			currentConsumer := *consumer
			currentRegistry := *registry
			currentData := policyData(&currentConsumer, &currentRegistry)
			currentData.GatewayID = data.GatewayID
			if test.mutateData != nil {
				test.mutateData(currentData)
			}
			identity := requests[0].Identity
			if test.mutateID != nil {
				test.mutateID(&identity)
			}
			source := key
			if test.mutateKey != nil {
				test.mutateKey(&source)
			}
			policy := NewSubscriptionPolicyWithUpstream(
				&stubDataFinder{data: currentData},
				passthroughScoper{},
				nil,
				nil,
				nil,
				connector,
			)
			ok, err := policy.AuthorizeEvent(ctx, identity, source, test.kind)
			if !errors.Is(err, test.wantErr) {
				t.Fatalf("AuthorizeEvent() error = %v, want %v", err, test.wantErr)
			}
			if ok != test.wantOK {
				t.Fatalf("AuthorizeEvent() ok = %v, want %v", ok, test.wantOK)
			}
			if connector.prepareCalls.Load() != 0 {
				t.Fatalf("AuthorizeEvent() Prepare() calls = %d, want 0", connector.prepareCalls.Load())
			}
		})
	}
}

func TestSubscriptionPolicyAuthorizeEventTransientFailureEmitsNothing(t *testing.T) {
	t.Parallel()
	key := multiplexerTestKey("policy-transient")
	policy := NewSubscriptionPolicyWithUpstream(
		&stubDataFinder{err: errors.New("database unavailable")},
		passthroughScoper{},
		nil,
		nil,
		nil,
		connectorForPreparedKey(key),
	)
	ok, err := policy.AuthorizeEvent(
		context.Background(),
		SubscriptionIdentity{GatewayID: ids.New[ids.GatewayKind]().String()},
		key,
		NotificationToolsListChanged,
	)
	if err == nil || errors.Is(err, ErrSubscriptionRevoked) || errors.Is(err, ErrSubscriptionSourceChanged) {
		t.Fatalf("AuthorizeEvent() error = %v, want transient failure", err)
	}
	if ok {
		t.Fatal("transient authorization failure must not authorize")
	}
}

// The digest must depend on the surface, not on the order the upstream happened
// to serialize its payload in.
func TestEncodeSurface_IsStableAcrossShuffledPayloadKeys(t *testing.T) {
	t.Parallel()
	keys := []string{
		`"name":"create_issue"`,
		`"description":"opens an issue"`,
		`"inputSchema":{"type":"object"}`,
		`"title":"Create issue"`,
	}
	name := func(tool Tool) string { return tool.Name }

	var want string
	for i := range 100 {
		shuffled := slices.Clone(keys)
		rand.Shuffle(len(shuffled), func(a, b int) { shuffled[a], shuffled[b] = shuffled[b], shuffled[a] })
		raw := []byte("{")
		for j, part := range shuffled {
			if j > 0 {
				raw = append(raw, ',')
			}
			raw = append(raw, part...)
		}
		raw = append(raw, '}')

		var tool Tool
		if err := json.Unmarshal(raw, &tool); err != nil {
			t.Fatalf("decode tool: %v", err)
		}
		encoded, err := encodeSurface([]Tool{tool}, name)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		got := digestOf(encoded)
		if i == 0 {
			want = got
			continue
		}
		if got != want {
			t.Fatalf("digest = %q on repetition %d, want %q", got, i, want)
		}
	}
}

func TestEncodeSurface_IgnoresTheOrderItemsArriveIn(t *testing.T) {
	t.Parallel()
	name := func(tool Tool) string { return tool.Name }
	ascending, err := encodeSurface(tools("a", "b", "c"), name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	descending, err := encodeSurface(tools("c", "b", "a"), name)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if digestOf(ascending) != digestOf(descending) {
		t.Fatal("the digest must not depend on the order the registries answered in")
	}
}

func TestSubscriptionDigestsUseAtLeast128Bits(t *testing.T) {
	t.Parallel()
	reg := mcpRegistry(t, "github", "https://a.example.com/mcp")
	consumer := policyConsumer(t, ids.New[ids.AuthKind](), reg)
	data := policyData(consumer, reg)
	rc, ok := data.MatchPath(appconsumer.MCPPath(policyTestSlug))
	if !ok {
		t.Fatal("consumer path did not resolve")
	}

	if got := len(digestOf([]byte("surface"))); got < 32 {
		t.Fatalf("surface digest hex length = %d, want at least 32", got)
	}
	if got := len(SurfaceConfigFingerprint(rc)); got < 32 {
		t.Fatalf("config fingerprint hex length = %d, want at least 32", got)
	}
}

func TestReauthBudget_ClampsToTheBoundedWindow(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		reauth    time.Duration
		keepalive time.Duration
		want      time.Duration
	}{
		{
			name:      "the defaults leave half a keepalive",
			reauth:    30 * time.Second,
			keepalive: 15 * time.Second,
			want:      7500 * time.Millisecond,
		},
		{
			name:      "the shortest cadence wins",
			keepalive: 60 * time.Second,
			reauth:    12 * time.Second,
			want:      6 * time.Second,
		},
		{
			name:      "a long cadence is clamped to the ceiling",
			reauth:    5 * time.Minute,
			keepalive: 4 * time.Minute,
			want:      reauthBudgetCeiling,
		},
		{
			name:      "a short cadence is clamped to the floor",
			reauth:    5 * time.Second,
			keepalive: 1 * time.Second,
			want:      reauthBudgetFloor,
		},
		{
			name:      "a disabled keepalive falls back on the re-auth interval",
			reauth:    6 * time.Second,
			keepalive: 0,
			want:      3 * time.Second,
		},
		{
			name:      "a disabled re-auth interval falls back on the keepalive",
			reauth:    0,
			keepalive: 6 * time.Second,
			want:      3 * time.Second,
		},
		{
			name: "both disabled still yields the floor",
			want: reauthBudgetFloor,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := ReauthBudget(tc.reauth, tc.keepalive); got != tc.want {
				t.Fatalf("ReauthBudget(%s, %s) = %s, want %s", tc.reauth, tc.keepalive, got, tc.want)
			}
		})
	}
}

// The budget must always leave the terminal frame its full write margin, which is
// only true while the ceiling stays under the fixed lifetime margin.
func TestReauthBudget_CeilingStaysUnderTheLifetimeMargin(t *testing.T) {
	t.Parallel()
	const lifetimeMargin = 10 * time.Second
	if reauthBudgetCeiling >= lifetimeMargin {
		t.Fatalf("ceiling %s must stay below the %s lifetime margin", reauthBudgetCeiling, lifetimeMargin)
	}
	if reauthBudgetFloor > reauthBudgetCeiling {
		t.Fatalf("floor %s must not exceed the ceiling %s", reauthBudgetFloor, reauthBudgetCeiling)
	}
}

func waitForFlightWaiters(
	t *testing.T,
	policy *subscriptionPolicy,
	key reauthFlightKey,
	want int,
) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		policy.flights.mu.Lock()
		call := policy.flights.calls[key]
		got := 0
		if call != nil {
			got = call.waiters
		}
		policy.flights.mu.Unlock()
		if got >= want {
			return
		}
		select {
		case <-deadline:
			t.Fatalf("flight waiters = %d, want %d", got, want)
		default:
			runtime.Gosched()
		}
	}
}

func awaitFinderStarts(t *testing.T, started <-chan struct{}, want int) {
	t.Helper()
	for range want {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("finder starts did not reach %d", want)
		}
	}
}
