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

package proxy_test

import (
	"context"
	"slices"
	"testing"
	"time"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	appproxy "github.com/NeuralTrust/TrustGate/pkg/app/proxy"
	approuting "github.com/NeuralTrust/TrustGate/pkg/app/routing"
	catalogdomain "github.com/NeuralTrust/TrustGate/pkg/domain/catalog"
	domainconsumer "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	routingdomain "github.com/NeuralTrust/TrustGate/pkg/domain/routing"
	infracontext "github.com/NeuralTrust/TrustGate/pkg/infra/context"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type storeCatalog map[string][]string

func (c storeCatalog) Lists(_ context.Context, provider, model string) appcatalog.Verdict {
	models, ok := c[provider]
	switch {
	case !ok:
		return appcatalog.VerdictUnknown
	case slices.Contains(models, model):
		return appcatalog.VerdictListed
	default:
		return appcatalog.VerdictAbsent
	}
}

func (storeCatalog) InvalidateCache() {}

func (storeCatalog) ListProviders(context.Context) ([]catalogdomain.Provider, error) { return nil, nil }

func (c storeCatalog) ListModels(_ context.Context, provider string) ([]catalogdomain.Model, error) {
	models := make([]catalogdomain.Model, 0, len(c[provider]))
	for _, slug := range c[provider] {
		models = append(models, catalogdomain.Model{Slug: slug})
	}
	return models, nil
}

var workedCatalog = storeCatalog{
	"openai":    {"gpt-4.1", "gpt6"},
	"anthropic": {"opus-5.5", "opus-4.8"},
	"deepseek":  {"deepseek-chat"},
	"mistral":   {"mistral-large"},
}

type storeRegistry struct {
	provider, def    string
	allowed          []string
	fallback, pooled bool
}

type storeGrant struct {
	name, pool string
	level      domainconsumer.GrantLevel
	priority   int
	grantedAt  time.Duration
	regs       []storeRegistry
}

type storeFixture struct {
	authID ids.AuthID
	data   *appconsumer.Data
}

func newStoreFixture(grants ...storeGrant) storeFixture {
	gw, authID := ids.New[ids.GatewayKind](), ids.New[ids.AuthKind]()
	base := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	consumers := make([]appconsumer.RoutableConsumer, 0, len(grants))
	for i, g := range grants {
		link := domainconsumer.AuthLink{Level: g.level, Priority: g.priority, GrantedAt: base.Add(time.Duration(i)*time.Hour + g.grantedAt)}
		rc := appconsumer.RoutableConsumer{Consumer: &domainconsumer.Consumer{
			ID: ids.New[ids.ConsumerKind](), GatewayID: gw, Name: g.name, Active: true,
			Audience: domainconsumer.AudiencePersonal, AuthIDs: []ids.AuthID{authID},
			AuthLinks: map[ids.AuthID]domainconsumer.AuthLink{authID: link},
			Fallback:  &domainconsumer.Fallback{Enabled: true}, ModelPolicies: domainconsumer.ModelPolicies{},
		}}
		var members []domainconsumer.LBPoolMember
		for _, r := range g.regs {
			reg := backendFor(gw, r.provider)
			rc.Consumer.ModelPolicies[reg.ID] = domainconsumer.ModelPolicy{Allowed: r.allowed, Default: r.def}
			if r.fallback {
				rc.FallbackBackends = append(rc.FallbackBackends, reg)
			} else {
				rc.Registries = append(rc.Registries, reg)
			}
			if r.pooled {
				members = append(members, domainconsumer.LBPoolMember{RegistryID: reg.ID})
			}
		}
		if g.pool != "" {
			rc.Consumer.LBConfig = &domainconsumer.LBConfig{Enabled: true, PoolAlias: g.pool, Members: members}
		}
		consumers = append(consumers, rc)
	}
	return storeFixture{authID: authID, data: appconsumer.NewData(gw, consumers)}
}

func storeRequest(model, capability, path string) *infracontext.RequestContext {
	req := &infracontext.RequestContext{ProxyCapability: capability, Path: path, Body: chatBody(model)}
	switch {
	case model == "" && capability == "":
		req.Body = []byte(`{"messages":[]}`)
	case model == "":
		req.Body = nil
	}
	return req
}

func (fx storeFixture) choose(selector appproxy.StoreSelector, req *infracontext.RequestContext) (*appproxy.StoreSelection, error) {
	return selector.Select(context.Background(), appproxy.StoreSelectInput{
		Links: fx.data.StoreLinks(fx.authID), Data: fx.data, Request: req,
	})
}

func newStoreSelector(catalog appcatalog.ModelListing) appproxy.StoreSelector {
	return appproxy.NewStoreSelector(approuting.NewResolver(), catalog, newTestLogger())
}

func keptProviders(sel *appproxy.StoreSelection) []string {
	var out []string
	for _, reg := range append(slices.Clone(sel.Link.Consumer.Registries), sel.Link.Consumer.FallbackBackends...) {
		if sel.Keep == nil || sel.Keep(routingdomain.Candidate{Registry: reg}) {
			out = append(out, reg.Provider())
		}
	}
	return out
}

const (
	levelUser  = domainconsumer.GrantLevelUser
	levelGroup = domainconsumer.GrantLevelGroup
	levelAll   = domainconsumer.GrantLevelAll
)

var (
	grantA = storeGrant{name: "A", level: levelGroup, priority: 1,
		regs: []storeRegistry{{provider: "openai", def: "gpt-4o"}, {provider: "deepseek", fallback: true}}}
	grantB = storeGrant{name: "B", level: levelGroup, priority: 1, regs: []storeRegistry{{provider: "anthropic", def: "opus-4.8"}}}
	grantC = storeGrant{name: "C", level: levelGroup, priority: 1,
		regs: []storeRegistry{{provider: "anthropic", allowed: []string{"opus-5.5"}, def: "opus-5.5"}}}
	grantD = storeGrant{name: "D", level: levelUser, priority: 1,
		regs: []storeRegistry{{provider: "openai", allowed: []string{"gpt6"}, def: "gpt6"}}}
)

func withPriority(g storeGrant, priority int) storeGrant {
	g.priority = priority
	return g
}

func openAIGrant(name string, level domainconsumer.GrantLevel, grantedAt time.Duration, allowed ...string) storeGrant {
	return storeGrant{name: name, level: level, priority: 1, grantedAt: grantedAt,
		regs: []storeRegistry{{provider: "openai", allowed: allowed}}}
}

type storeCase struct {
	name             string
	grants           []storeGrant
	catalog          storeCatalog
	model, want      string
	capability, path string
	kept             []string
	nilKeep          bool
	err, notErr      error
}

func runStoreCases(t *testing.T, cases []storeCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			catalog := tc.catalog
			if catalog == nil {
				catalog = workedCatalog
			}
			req := storeRequest(tc.model, tc.capability, tc.path)
			sel, err := newStoreFixture(tc.grants...).choose(newStoreSelector(catalog), req)
			if tc.err != nil {
				require.ErrorIs(t, err, tc.err)
				assert.Nil(t, sel)
				if tc.notErr != nil {
					assert.NotErrorIs(t, err, tc.notErr)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.want, sel.Link.Consumer.Consumer.Name)
			if tc.kept != nil {
				assert.Equal(t, tc.kept, keptProviders(sel))
			}
			if tc.nilKeep {
				assert.Nil(t, sel.Keep)
			}
		})
	}
}

func TestStoreSelector_WorkedExample(t *testing.T) {
	dFallbackDefault := storeGrant{name: "D", level: levelUser, priority: 1, regs: []storeRegistry{
		{provider: "anthropic", allowed: []string{"opus-5.5"}}, {provider: "openai", def: "gpt6", fallback: true},
	}}
	worked := []storeGrant{grantA, grantB, grantC, grantD}
	withoutD := []storeGrant{grantA, grantB, grantC}
	denied := appproxy.ErrNoStoreConsumer
	runStoreCases(t, []storeCase{
		{name: "gpt-4.1 is denied", grants: worked, model: "gpt-4.1", err: denied},
		{name: "gpt6 goes to D", grants: worked, model: "gpt6", want: "D"},
		{name: "opus-5.5 goes to C", grants: worked, model: "opus-5.5", want: "C"},
		{name: "opus-4.8 goes to B", grants: worked, model: "opus-4.8", want: "B"},
		{name: "no model goes to D", grants: worked, want: "D"},
		{name: "qualified gpt-4.1 is denied", grants: worked, model: "@openai/gpt-4.1", err: denied},
		{name: "auto goes to D", grants: worked, model: "auto", want: "D"},
		{name: "without D gpt-4.1 goes to A unfiltered", grants: withoutD, model: "gpt-4.1", want: "A",
			nilKeep: true, kept: []string{"openai", "deepseek"}},
		{name: "without D deepseek-chat is denied", grants: withoutD, model: "deepseek-chat", err: denied},
		{name: "B at priority 0 wins opus-5.5", grants: []storeGrant{grantA, withPriority(grantB, 0), grantC, grantD},
			model: "opus-5.5", want: "B"},
		{name: "no model skips a user link whose only default is on a fallback", grants: []storeGrant{grantA, dFallbackDefault},
			want: "A"},
	})
}

func TestStoreSelector_SubstitutionAndAdmission(t *testing.T) {
	mixedA := storeGrant{name: "A", level: levelGroup, priority: 1, regs: []storeRegistry{{provider: "openai"}, {provider: "mistral"}}}
	dWithFallback := withFallback(grantD, "anthropic")
	pooledFallback := storeGrant{name: "P", level: levelGroup, priority: 1, pool: "fast", regs: []storeRegistry{
		{provider: "openai", def: "gpt-4.1"}, {provider: "deepseek", fallback: true, pooled: true},
	}}
	pooledSubstituted := storeGrant{name: "P", level: levelGroup, priority: 1, pool: "fast", regs: []storeRegistry{
		{provider: "openai", pooled: true}, {provider: "mistral", def: "mistral-large"},
	}}
	userWithoutPools := storeGrant{name: "U", level: levelUser, priority: 1, regs: []storeRegistry{{provider: "anthropic", def: "opus-4.8"}}}
	denied := appproxy.ErrNoStoreConsumer
	runStoreCases(t, []storeCase{
		{name: "user link narrows a provider", grants: []storeGrant{grantA, grantD}, model: "gpt-4.1", err: denied},
		{name: "substituted registry of a surviving group consumer does not admit",
			grants: []storeGrant{mixedA, grantD}, model: "gpt-4.1", err: denied},
		{name: "other providers of a group consumer survive", grants: []storeGrant{mixedA, grantD},
			model: "mistral-large", want: "A", kept: []string{"mistral"}},
		{name: "user fallback provider is not substituted", grants: []storeGrant{dWithFallback, grantB},
			model: "opus-4.8", want: "B", kept: []string{"anthropic"}},
		{name: "fallback does not admit", grants: []storeGrant{grantA}, model: "deepseek-chat", err: denied},
		{name: "pool member reached only as fallback does not admit", grants: []storeGrant{userWithoutPools, pooledFallback},
			model: "pool:fast", err: denied, notErr: routingdomain.ErrUnknownPoolAlias},
		{name: "known pool alias with every member substituted", grants: []storeGrant{grantD, pooledSubstituted},
			model: "pool:fast", err: denied, notErr: routingdomain.ErrUnknownPoolAlias},
	})
}

func withFallback(g storeGrant, provider string) storeGrant {
	g.regs = append(slices.Clone(g.regs), storeRegistry{provider: provider, fallback: true})
	return g
}

func TestStoreSelector_ListingAndOrdering(t *testing.T) {
	glob, literal, open := openAIGrant("E", levelAll, 0, "gpt-4*"), openAIGrant("L", levelAll, 0, "gpt-4.1"), openAIGrant("F", levelAll, 0)
	g1, g2 := openAIGrant("G1", levelGroup, 3*time.Hour, "gpt-4.1"), openAIGrant("G2", levelGroup, 0, "gpt-4.1")
	runStoreCases(t, []storeCase{
		{name: "absent verdict keeps gpt models off anthropic", grants: []storeGrant{grantB},
			catalog: storeCatalog{"anthropic": {"opus-5.5"}}, model: "gpt-4.1", err: appproxy.ErrNoStoreConsumer},
		{name: "unknown verdict keeps the candidate", grants: []storeGrant{grantB}, catalog: storeCatalog{},
			model: "gpt-4.1", want: "B"},
		{name: "specificity at equal level and priority", grants: []storeGrant{grantB, grantC}, model: "opus-5.5", want: "C"},
		{name: "priority before specificity", grants: []storeGrant{withPriority(grantB, 0), grantC}, model: "opus-5.5", want: "B"},
		{name: "glob before no allow-list", grants: []storeGrant{open, glob}, model: "gpt-4.1", want: "E"},
		{name: "literal entry before glob", grants: []storeGrant{glob, literal}, model: "gpt-4.1", want: "L"},
		{name: "oldest grant breaks a tie", grants: []storeGrant{g1, g2}, model: "gpt-4.1", want: "G2"},
	})
}

func TestStoreSelector_IntentKinds(t *testing.T) {
	p1 := storeGrant{name: "P1", level: levelGroup, priority: 1, pool: "fast",
		regs: []storeRegistry{{provider: "mistral", def: "mistral-large", pooled: true}}}
	p2 := storeGrant{name: "P2", level: levelUser, priority: 1, regs: []storeRegistry{{provider: "openai", def: "gpt6"}}}
	h := storeGrant{name: "H", level: levelGroup, priority: 1, regs: []storeRegistry{{provider: "groq", allowed: []string{"openai/gpt-oss-*"}}}}
	runStoreCases(t, []storeCase{
		{name: "pool alias", grants: []storeGrant{p1, p2}, model: "pool:fast", want: "P1"},
		{name: "unknown pool alias", grants: []storeGrant{p1, p2}, model: "pool:slow", err: routingdomain.ErrUnknownPoolAlias},
		{name: "auto", grants: []storeGrant{p1, p2}, model: "auto", want: "P2"},
		{name: "qualified reference", grants: []storeGrant{grantB, grantC}, model: "@anthropic/opus-5.5", want: "C"},
		{name: "qualified provider without a link", grants: []storeGrant{grantB, grantC}, model: "@openai/gpt-4o",
			err: appproxy.ErrNoStoreConsumer},
		{name: "empty model", grants: []storeGrant{grantA, grantD}, want: "D"},
		{name: "bare provider/model is a native short model", grants: []storeGrant{grantD, h},
			model: "openai/gpt-oss-120b", want: "H"},
		{name: "invalid model reference", grants: []storeGrant{grantD}, model: "@openai", err: routingdomain.ErrInvalidModelRef},
		{name: "no links", model: "gpt6", err: appproxy.ErrNoStoreConsumer},
		{name: "no links with a pool alias", model: "pool:fast", err: appproxy.ErrNoStoreConsumer,
			notErr: routingdomain.ErrUnknownPoolAlias},
	})
	require.ErrorIs(t, appproxy.ErrNoStoreConsumer, routingdomain.ErrModelDenied)
}

func TestStoreSelector_CapabilityRoutes(t *testing.T) {
	userAnthropic := storeGrant{name: "U", level: levelUser, priority: 1, regs: []storeRegistry{{provider: "anthropic", def: "opus-4.8"}}}
	groupOpenAI := storeGrant{name: "G", level: levelGroup, priority: 1,
		regs: []storeRegistry{{provider: "openai", allowed: []string{"text-embedding-3-small"}}}}
	anthropicNoDefault := storeGrant{name: "B", level: levelGroup, priority: 1, regs: []storeRegistry{{provider: "anthropic"}}}
	runStoreCases(t, []storeCase{
		{name: "embeddings skip a user link whose provider lacks them", grants: []storeGrant{userAnthropic, groupOpenAI},
			capability: "embeddings", model: "text-embedding-3-small", want: "G"},
		{name: "embeddings with no capable link", grants: []storeGrant{userAnthropic},
			capability: "embeddings", model: "text-embedding-3-small", err: appproxy.ErrNoStoreConsumer},
		{name: "files id picks the provider that owns it, without a default", grants: []storeGrant{grantD, anthropicNoDefault},
			capability: "files", path: "/v1/files/file_011abc", want: "B"},
		{name: "openai files id goes to the user link", grants: []storeGrant{grantD, anthropicNoDefault},
			capability: "files", path: "/v1/files/file-abc123", want: "D"},
	})
}

func TestStoreSelector_SelectionCarriesTheRouting(t *testing.T) {
	mixedA := storeGrant{name: "A", level: levelGroup, priority: 1, regs: []storeRegistry{{provider: "openai"}, {provider: "mistral"}}}
	sel, err := newStoreFixture(mixedA, grantD).choose(newStoreSelector(workedCatalog), storeRequest("mistral-large", "", ""))
	require.NoError(t, err)
	assert.Equal(t, routingdomain.Intent{Model: "mistral-large"}, sel.Intent)
	assert.Equal(t, "mistral-large", sel.Ref)
	require.Len(t, sel.Candidates.Registries(), 1)
	assert.Equal(t, "mistral", sel.Candidates.Registries()[0].Provider())
}

func TestStoreSelector_RefusesAnAmbiguousChatBody(t *testing.T) {
	req := &infracontext.RequestContext{ProxyCapability: "chat", Body: []byte(`{"model":"gpt6","model":"gpt-4.1"}`)}
	sel, err := newStoreFixture(grantD).choose(newStoreSelector(workedCatalog), req)
	require.ErrorIs(t, err, appproxy.ErrAmbiguousRequestBody)
	assert.Nil(t, sel)
}
