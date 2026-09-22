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

package policy_test

import (
	"context"
	"errors"
	"testing"

	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/mock"
)

var credentialPaths = []string{"credentials.access_key_id", "credentials.secret_access_key"}

// credentialMockPlugin adapts a mockery Plugin mock to also implement
// appplugins.CredentialSettings, the RUN-1646 opt-in.
type credentialMockPlugin struct {
	*pluginmocks.Plugin
	paths []string
}

func (p *credentialMockPlugin) CredentialPaths() []string { return p.paths }

// newCredentialRegistryMock resolves slug to a plugin that declared paths as
// its credential-bearing settings. It is built independently rather than on
// top of newRegistryMock: a later Get(...) stub never overrides an earlier
// one for testify's mock (see newScopedRegistryMock's own comment), so this
// registers exactly one Get expectation, scoped to slug.
func newCredentialRegistryMock(t *testing.T, slug string, paths []string) *pluginmocks.Registry {
	t.Helper()
	reg := pluginmocks.NewRegistry(t)
	reg.EXPECT().ValidateStages(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().ValidateMode(mock.Anything, mock.Anything).Return(nil).Maybe()
	reg.EXPECT().Validate(mock.Anything, mock.Anything).Return(nil).Maybe()
	plugin := &credentialMockPlugin{Plugin: pluginmocks.NewPlugin(t), paths: paths}
	reg.EXPECT().Get(slug).Return(plugin, true).Maybe()
	return reg
}

func credsSettings(accessKey, secretKey string) map[string]any {
	return map[string]any{
		"guardrail_id": "gr-1",
		"credentials": map[string]any{
			"access_key_id":     accessKey,
			"secret_access_key": secretKey,
		},
	}
}

func TestUpdater_Update_ResolvesMaskedSettingsAgainstStored(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.Slug = "bedrock_guardrail"
	existing.Settings = credsSettings("AKIAREALVALUE", "sk-supersecretvalue1234")
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	masked := secret.MaskSettings(existing.Settings, credentialPaths)
	incoming := credsSettings(
		masked["credentials"].(map[string]any)["access_key_id"].(string),
		masked["credentials"].(map[string]any)["secret_access_key"].(string),
	)

	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		creds := p.Settings["credentials"].(map[string]any)
		return creds["access_key_id"] == "AKIAREALVALUE" && creds["secret_access_key"] == "sk-supersecretvalue1234"
	}), false).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).Once()

	updater := apppolicy.NewUpdater(
		repo, nil, freeLevels(t), newRegistryRepo(t),
		newCredentialRegistryMock(t, "bedrock_guardrail", credentialPaths),
		newCacheManager(), publisher, newTestLogger(), nil,
	)
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		Settings: &incoming,
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	creds := got.Settings["credentials"].(map[string]any)
	if creds["access_key_id"] != "AKIAREALVALUE" || creds["secret_access_key"] != "sk-supersecretvalue1234" {
		t.Fatalf("Settings = %#v, want the masked round-trip resolved to the stored real values", got.Settings)
	}
}

func TestUpdater_Update_NewSettingsValueReplacesStored(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.Slug = "bedrock_guardrail"
	existing.Settings = credsSettings("AKIAOLDVALUE", "sk-oldsecretvalue1234")
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	incoming := credsSettings("AKIANEWVALUE", "sk-newsecretvalue5678")
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		creds := p.Settings["credentials"].(map[string]any)
		return creds["access_key_id"] == "AKIANEWVALUE" && creds["secret_access_key"] == "sk-newsecretvalue5678"
	}), false).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).Once()

	updater := apppolicy.NewUpdater(
		repo, nil, freeLevels(t), newRegistryRepo(t),
		newCredentialRegistryMock(t, "bedrock_guardrail", credentialPaths),
		newCacheManager(), publisher, newTestLogger(), nil,
	)
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		Settings: &incoming,
	})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	creds := got.Settings["credentials"].(map[string]any)
	if creds["access_key_id"] != "AKIANEWVALUE" {
		t.Fatalf("access_key_id = %v, want the new value kept", creds["access_key_id"])
	}
}

// A masked literal with nothing stored to resolve against (this policy never
// had a real access_key_id) is not a credential and must be rejected, not
// silently written as an empty/garbage value.
func TestUpdater_Update_RejectsMaskedLiteralWithNothingStored(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t)
	existing.Slug = "bedrock_guardrail"
	existing.Settings = map[string]any{"guardrail_id": "gr-1"} // no credentials at all yet
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	incoming := credsSettings(secret.Redacted+"abcd", "sk-newsecretvalue5678")
	publisher := cachemocks.NewEventPublisher(t)

	updater := apppolicy.NewUpdater(
		repo, nil, freeLevels(t), newRegistryRepo(t),
		newCredentialRegistryMock(t, "bedrock_guardrail", credentialPaths),
		newCacheManager(), publisher, newTestLogger(), nil,
	)
	_, err := updater.Update(context.Background(), apppolicy.UpdateInput{
		ID:       existing.ID,
		Settings: &incoming,
	})
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
	repo.AssertNotCalled(t, "Update", mock.Anything, mock.Anything, mock.Anything)
	publisher.AssertNotCalled(t, "Publish", mock.Anything, mock.Anything)
}

// A plugin that never declared credential paths must go through Update
// exactly as before RUN-1646: no resolve, no reject, whatever Settings the
// client sent is stored as-is.
func TestUpdater_Update_SettingsForPluginWithoutDeclaredPathsIsUnaffected(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	existing := existingPolicy(t) // slug "rate_limiter"
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()

	incoming := map[string]any{"limit": 200}
	repo.EXPECT().Update(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		return p.Settings["limit"] == 200
	}), false).Return(nil).Once()

	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().
		Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).
		Return(nil).Once()

	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), newRegistryMock(t, nil), newCacheManager(), publisher, newTestLogger(), nil)
	got, err := updater.Update(context.Background(), apppolicy.UpdateInput{ID: existing.ID, Settings: &incoming})
	if err != nil {
		t.Fatalf("Update error: %v", err)
	}
	if got.Settings["limit"] != 200 {
		t.Fatalf("Settings = %#v, want limit=200 stored verbatim", got.Settings)
	}
}

// Create has nothing stored to resolve a masked value against, so any masked
// literal in a declared credential path must be rejected outright — most
// likely a client echoing a response it read elsewhere rather than typing a
// real credential.
func TestCreator_Create_RejectsMaskedLiteralSettings(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	creator := apppolicy.NewCreator(
		repo, freeLevels(t), newRegistryRepo(t),
		newCredentialRegistryMock(t, "bedrock_guardrail", credentialPaths),
		newCacheManager(), newTestLogger(), nil,
	)

	in := validCreateInput(ids.New[ids.GatewayKind]())
	in.Slug = "bedrock_guardrail"
	in.Settings = credsSettings(secret.Redacted+"abcd", "sk-newsecretvalue5678")

	_, err := creator.Create(context.Background(), in)
	if !errors.Is(err, commonerrors.ErrValidation) {
		t.Fatalf("err = %v, want ErrValidation", err)
	}
	repo.AssertNotCalled(t, "Save", mock.Anything, mock.Anything)
}

// Create with a genuine value (never masked) for a credential-bearing plugin
// must go through untouched.
func TestCreator_Create_WithRealCredentialSettingsSucceeds(t *testing.T) {
	t.Parallel()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().Save(mock.Anything, mock.MatchedBy(func(p *domain.Policy) bool {
		creds := p.Settings["credentials"].(map[string]any)
		return creds["access_key_id"] == "AKIAREALVALUE"
	})).Return(nil).Once()

	creator := apppolicy.NewCreator(
		repo, freeLevels(t), newRegistryRepo(t),
		newCredentialRegistryMock(t, "bedrock_guardrail", credentialPaths),
		newCacheManager(), newTestLogger(), nil,
	)

	in := validCreateInput(ids.New[ids.GatewayKind]())
	in.Slug = "bedrock_guardrail"
	in.Settings = credsSettings("AKIAREALVALUE", "sk-supersecretvalue1234")

	if _, err := creator.Create(context.Background(), in); err != nil {
		t.Fatalf("Create error: %v", err)
	}
}
