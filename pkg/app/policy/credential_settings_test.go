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
	"strings"
	"testing"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	pluginmocks "github.com/NeuralTrust/TrustGate/pkg/app/plugins/mocks"
	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/policy/mocks"
	"github.com/NeuralTrust/TrustGate/pkg/infra/cache/event"
	cachemocks "github.com/NeuralTrust/TrustGate/pkg/infra/cache/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

const (
	azureSlug   = "azure_content_safety"
	openaiSlug  = "openai_moderation"
	bedrockSlug = "bedrock_guardrail"
	armorSlug   = "google_model_armor"
	realKey     = "REAL-azure-key-0123456789"
)

// credPlugin is a registered plugin declaring credential paths.
type credPlugin struct {
	appplugins.Plugin
	paths []string
}

func (p credPlugin) CredentialPaths() []string { return p.paths }

// credDestPlugin also declares destinations bound to its credentials.
type credDestPlugin struct {
	credPlugin
	dests []string
}

func (p credDestPlugin) CredentialDestinations() []string { return p.dests }

// credentialRegistryMock registers the three plugins whose paths the tests
// exercise. Validation always passes: the credential rules under test run
// before it, and a rejected write must not depend on it.
func credentialRegistryMock(t *testing.T) *pluginmocks.Registry {
	t.Helper()
	reg := newValidatingRegistryMock(t, nil)
	decl := map[string][]string{
		azureSlug:  {"api_key"},
		openaiSlug: {"api_key"},
		armorSlug:  {"credentials.service_account_json"},
		bedrockSlug: {
			"credentials.access_key_id",
			"credentials.secret_access_key",
			"credentials.session_token",
		},
	}
	dests := map[string][]string{azureSlug: {"endpoint"}, armorSlug: {"location", "project"}}
	for slug, paths := range decl {
		var plugin appplugins.Plugin = credPlugin{Plugin: pluginmocks.NewPlugin(t), paths: paths}
		if d, ok := dests[slug]; ok {
			plugin = credDestPlugin{credPlugin: credPlugin{Plugin: pluginmocks.NewPlugin(t), paths: paths}, dests: d}
		}
		reg.EXPECT().Get(slug).Return(plugin, true).Maybe()
	}
	return reg
}

func storedPolicy(t *testing.T, slug string, settings map[string]any) *domain.Policy {
	t.Helper()
	p, err := domain.NewPolicy(ids.New[ids.GatewayKind](), "p", slug, true, 0, false, settings, nil, "", domain.ModeEnforce, nil)
	require.NoError(t, err)
	return p
}

// updateWith runs one Update against a stored policy and returns what the
// repository was asked to persist (nil when nothing was written) and the error.
func updateWith(t *testing.T, existing *domain.Policy, in apppolicy.UpdateInput) (map[string]any, error) {
	t.Helper()
	repo := repomocks.NewRepository(t)
	repo.EXPECT().FindByID(mock.Anything, existing.ID).Return(existing, nil).Once()
	var saved map[string]any
	repo.EXPECT().Update(mock.Anything, mock.Anything, false).
		Run(func(_ context.Context, p *domain.Policy, _ bool) { saved = p.Settings }).
		Return(nil).Maybe()
	publisher := cachemocks.NewEventPublisher(t)
	publisher.EXPECT().Publish(mock.Anything, event.InvalidateGatewayDataEvent{GatewayID: existing.GatewayID.String()}).Return(nil).Maybe()

	in.ID = existing.ID
	updater := apppolicy.NewUpdater(repo, nil, freeLevels(t), newRegistryRepo(t), credentialRegistryMock(t), newCacheManager(), publisher, newTestLogger(), nil)
	_, err := updater.Update(context.Background(), in)
	return saved, err
}

func bedrockStored(token string) map[string]any {
	return map[string]any{
		"guardrail_id": "gr-1",
		"credentials": map[string]any{
			"aws_region":        "eu-west-1",
			"access_key_id":     "AKIAREAL000000000001",
			"secret_access_key": "REAL-secret-000000000002",
			"session_token":     token,
		},
	}
}

func TestUpdater_Update_MaskedCredentialKeepsTheStoredOne(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey, "endpoint": "https://a"})

	saved, err := updateWith(t, existing, apppolicy.UpdateInput{
		Settings: &map[string]any{"api_key": "***6789", "endpoint": "https://a", "model": "m2"},
	})

	require.NoError(t, err)
	assert.Equal(t, realKey, saved["api_key"], "a masked echo must not overwrite the real credential")
	assert.Equal(t, "m2", saved["model"], "non-credential fields still update")
}

func TestUpdater_Update_OmittedAndEmptyCredentialClearTheStoredOne(t *testing.T) {
	t.Parallel()
	for name, settings := range map[string]map[string]any{
		"omitted": {"endpoint": "https://b"},
		"empty":   {"api_key": "", "endpoint": "https://b"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey, "endpoint": "https://a"})
			saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: &settings})
			require.NoError(t, err) // required-field validation is stubbed here; it is what rejects a cleared key
			assert.Empty(t, saved["api_key"], "an update replaces settings wholesale: what is not sent is cleared")
		})
	}
}

func TestUpdater_Update_ANewCredentialReplacesTheStoredOne(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey})
	saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: &map[string]any{"api_key": "brand-new"}})
	require.NoError(t, err)
	assert.Equal(t, "brand-new", saved["api_key"])
}

func TestUpdater_Update_MaskedCredentialWithNothingStoredIsRejected(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"endpoint": "https://a"})
	saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: &map[string]any{"api_key": "***6789"}})
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.Nil(t, saved, "a mask must never be persisted as a credential")
}

func TestUpdater_Update_NonStringCredentialIsRejected(t *testing.T) {
	t.Parallel()
	for name, v := range map[string]any{"number": float64(42), "object": map[string]any{"a": "b"}, "bool": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey})
			saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: &map[string]any{"api_key": v}})
			require.ErrorIs(t, err, commonerrors.ErrValidation)
			assert.Nil(t, saved)
		})
	}
}

// An update replaces settings wholesale, so an explicit null clears exactly like
// omitting does. The bedrock STS session_token has to be clearable.
func TestUpdater_Update_ExplicitNullClearsOnlyThatCredential(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, bedrockSlug, bedrockStored("REAL-sts-token-000000003"))

	saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: &map[string]any{
		"guardrail_id": "gr-1",
		"credentials": map[string]any{
			"aws_region":        "eu-west-1",
			"access_key_id":     "***0001",
			"secret_access_key": "***0002",
			"session_token":     nil,
		},
	}})

	require.NoError(t, err)
	creds := saved["credentials"].(map[string]any)
	assert.NotContains(t, creds, "session_token", "null clears the field")
	assert.Equal(t, "AKIAREAL000000000001", creds["access_key_id"])
	assert.Equal(t, "REAL-secret-000000000002", creds["secret_access_key"])
}

func TestUpdater_Update_AMaskThatIsNotTheStoredOneIsRejected(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey})
	saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: &map[string]any{"api_key": "***zzzz"}})
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.Nil(t, saved)
}

// Console flow: Bedrock session_token is written only when non-empty, so blanking
// it omits it. That must clear it, while an echoed mask keeps it.
func TestUpdater_Update_BedrockSessionTokenOmittedIsClearedAndMaskedIsKept(t *testing.T) {
	t.Parallel()
	body := func(token any, omit bool) *map[string]any {
		c := map[string]any{"access_key_id": "***0001", "secret_access_key": "***0002"}
		if !omit {
			c["session_token"] = token
		}
		return &map[string]any{"guardrail_id": "gr-1", "credentials": c}
	}
	t.Run("omitted is cleared", func(t *testing.T) {
		t.Parallel()
		existing := storedPolicy(t, bedrockSlug, bedrockStored("REAL-sts-token-000000003"))
		saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: body(nil, true)})
		require.NoError(t, err)
		assert.NotContains(t, saved["credentials"], "session_token")
	})
	t.Run("masked echo is kept", func(t *testing.T) {
		t.Parallel()
		existing := storedPolicy(t, bedrockSlug, bedrockStored("REAL-sts-token-000000003"))
		saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: body("***0003", false)})
		require.NoError(t, err)
		assert.Equal(t, "REAL-sts-token-000000003", saved["credentials"].(map[string]any)["session_token"])
	})
}

// Console flow: Bedrock static -> role omits the three static keys. They must
// not survive in storage.
func TestUpdater_Update_BedrockStaticToRoleClearsTheStaticKeys(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, bedrockSlug, bedrockStored("REAL-sts-token-000000003"))
	saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: &map[string]any{
		"guardrail_id": "gr-1",
		"credentials":  map[string]any{"use_role": true, "role_arn": "arn:aws:iam::1:role/x", "aws_region": "eu-west-1"},
	}})
	require.NoError(t, err)
	creds := saved["credentials"].(map[string]any)
	for _, k := range []string{"access_key_id", "secret_access_key", "session_token"} {
		assert.NotContains(t, creds, k)
	}
}

// Console flow: Model Armor explicit -> impersonate drops service_account_json.
// Restoring it would leave both fields set, which the plugin rejects.
func TestUpdater_Update_ModelArmorExplicitToImpersonateDropsTheServiceAccountJSON(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, armorSlug, map[string]any{
		"project": "p", "location": "l", "template": "t",
		"credentials": map[string]any{"service_account_json": `{"type":"service_account","k":"REAL"}`},
	})
	saved, err := updateWith(t, existing, apppolicy.UpdateInput{Settings: &map[string]any{
		"project": "p", "location": "l", "template": "t",
		"credentials": map[string]any{"impersonate_service_account": "sa@p.iam.gserviceaccount.com"},
	}})
	require.NoError(t, err)
	creds := saved["credentials"].(map[string]any)
	assert.NotContains(t, creds, "service_account_json")
	assert.Equal(t, "sa@p.iam.gserviceaccount.com", creds["impersonate_service_account"])
}

// A plugin change repoints the policy at another vendor. The stored credential
// belongs to the old plugin and must never stand in for the new plugin's.
func TestUpdater_Update_PluginChangeDoesNotResolveAgainstStoredSettings(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey, "endpoint": "https://a"})

	saved, err := updateWith(t, existing, apppolicy.UpdateInput{
		Slug:     ptr(openaiSlug),
		Settings: &map[string]any{"api_key": "***6789"},
	})

	require.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.Nil(t, saved, "the Azure key must not be carried over to the OpenAI plugin")
}

func TestUpdater_Update_PluginChangeWithOmittedCredentialDoesNotInheritTheOldOne(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey})
	saved, err := updateWith(t, existing, apppolicy.UpdateInput{
		Slug:     ptr(openaiSlug),
		Settings: &map[string]any{"model": "omni-moderation-latest"},
	})
	require.NoError(t, err) // the plugin's own required-field check (stubbed here) is what rejects a missing key
	assert.NotContains(t, saved, "api_key", "a credential saved for another plugin is not resolved in")
}

func TestUpdater_Update_PluginChangeWithAFreshCredentialIsAccepted(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey})
	saved, err := updateWith(t, existing, apppolicy.UpdateInput{
		Slug:     ptr(openaiSlug),
		Settings: &map[string]any{"api_key": "sk-openai-fresh"},
	})
	require.NoError(t, err)
	assert.Equal(t, "sk-openai-fresh", saved["api_key"])
}

func TestUpdater_Update_PluginChangeWithoutSettingsRefusesToCarryCredentialsAcross(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey})
	saved, err := updateWith(t, existing, apppolicy.UpdateInput{Slug: ptr(openaiSlug)})
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.Nil(t, saved)
}

func TestUpdater_Update_PluginChangeWithoutSettingsIsFineWhenNoCredentialIsStored(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"endpoint": "https://a"})
	_, err := updateWith(t, existing, apppolicy.UpdateInput{Slug: ptr(openaiSlug)})
	require.NoError(t, err)
}

func createWith(t *testing.T, slug string, settings map[string]any) (map[string]any, error) {
	t.Helper()
	repo := repomocks.NewRepository(t)
	var saved map[string]any
	repo.EXPECT().Save(mock.Anything, mock.Anything).
		Run(func(_ context.Context, p *domain.Policy) { saved = p.Settings }).
		Return(nil).Maybe()
	creator := apppolicy.NewCreator(repo, freeLevels(t), newRegistryRepo(t), credentialRegistryMock(t), newCacheManager(), newTestLogger(), nil)
	in := validCreateInput(ids.New[ids.GatewayKind]())
	in.Slug = slug
	in.Settings = settings
	_, err := creator.Create(context.Background(), in)
	return saved, err
}

func TestCreator_Create_RejectsAMaskedCredential(t *testing.T) {
	t.Parallel()
	saved, err := createWith(t, azureSlug, map[string]any{"api_key": "***6789"})
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.Nil(t, saved)

	saved, err = createWith(t, bedrockSlug, map[string]any{"credentials": map[string]any{"session_token": "***"}})
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.Nil(t, saved)
}

func TestCreator_Create_RejectsANonStringCredential(t *testing.T) {
	t.Parallel()
	saved, err := createWith(t, azureSlug, map[string]any{"api_key": float64(42)})
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.Nil(t, saved)
}

func TestCreator_Create_AcceptsARealCredential(t *testing.T) {
	t.Parallel()
	saved, err := createWith(t, azureSlug, map[string]any{"api_key": realKey})
	require.NoError(t, err)
	assert.Equal(t, realKey, saved["api_key"])
}

func TestCreator_Create_RejectsACaseVariantCredentialKey(t *testing.T) {
	t.Parallel()
	saved, err := createWith(t, azureSlug, map[string]any{"API_KEY": realKey})
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.Nil(t, saved, "a case-variant key must not be stored: it would be returned in the clear")

	saved, err = createWith(t, bedrockSlug, map[string]any{"Credentials": map[string]any{"secret_access_key": "x"}})
	require.ErrorIs(t, err, commonerrors.ErrValidation)
	assert.Nil(t, saved)
}

func TestUpdater_Update_RejectsACaseVariantCredentialKey(t *testing.T) {
	t.Parallel()
	for name, settings := range map[string]map[string]any{
		"mask":     {"API_KEY": "***6789"},
		"newvalue": {"Api_Key": "sk-new"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			saved, err := updateWith(t, storedPolicy(t, azureSlug, map[string]any{"api_key": realKey}), apppolicy.UpdateInput{Settings: &settings})
			require.ErrorIs(t, err, commonerrors.ErrValidation)
			assert.Nil(t, saved)
		})
	}
}

// A caller who can edit a policy but never read its secret must not be able to
// keep the secret and aim it elsewhere by echoing the mask with a new destination.
func TestUpdater_Update_MaskedCredentialWithAChangedDestinationIsRejected(t *testing.T) {
	t.Parallel()
	armorStored := func() *domain.Policy {
		return storedPolicy(t, armorSlug, map[string]any{
			"project": "p", "location": "us-central1", "template": "t",
			"credentials": map[string]any{"service_account_json": `{"k":"REAL-0123456789"}`},
		})
	}
	armorBody := func(field, value string) map[string]any {
		m := map[string]any{
			"project": "p", "location": "us-central1", "template": "t",
			"credentials": map[string]any{"service_account_json": secret.Mask(`{"k":"REAL-0123456789"}`)},
		}
		if field != "" {
			m[field] = value
		}
		return m
	}
	tests := []struct {
		name     string
		existing *domain.Policy
		body     map[string]any
		wantErr  bool
		wantKept string
	}{
		{"azure changed endpoint", storedPolicy(t, azureSlug, map[string]any{"api_key": realKey, "endpoint": "https://a.example"}),
			map[string]any{"api_key": "***6789", "endpoint": "https://attacker.example"}, true, ""},
		{"azure unchanged endpoint", storedPolicy(t, azureSlug, map[string]any{"api_key": realKey, "endpoint": "https://a.example"}),
			map[string]any{"api_key": "***6789", "endpoint": "https://a.example"}, false, realKey},
		{"azure endpoint case variant", storedPolicy(t, azureSlug, map[string]any{"api_key": realKey, "endpoint": "https://a.example"}),
			map[string]any{"api_key": "***6789", "endpoint": "https://a.example", "Endpoint": "https://attacker.example"}, true, ""},
		{"model armor changed location", armorStored(), armorBody("location", "europe-west4"), true, ""},
		{"model armor changed project", armorStored(), armorBody("project", "other"), true, ""},
		{"model armor unchanged", armorStored(), armorBody("", ""), false, `{"k":"REAL-0123456789"}`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			saved, err := updateWith(t, tt.existing, apppolicy.UpdateInput{Settings: &tt.body})
			if tt.wantErr {
				require.ErrorIs(t, err, commonerrors.ErrValidation)
				if !strings.Contains(tt.name, "case variant") {
					assert.Contains(t, err.Error(), "re-enter the credential")
				}
				assert.Nil(t, saved)
				return
			}
			require.NoError(t, err)
			if v, ok := saved["api_key"]; ok {
				assert.Equal(t, tt.wantKept, v)
			} else {
				assert.Equal(t, tt.wantKept, saved["credentials"].(map[string]any)["service_account_json"])
			}
		})
	}
}

func TestUpdater_Update_ANewCredentialMayMoveTheDestination(t *testing.T) {
	t.Parallel()
	existing := storedPolicy(t, azureSlug, map[string]any{"api_key": realKey, "endpoint": "https://a.example"})
	saved, err := updateWith(t, existing, apppolicy.UpdateInput{
		Settings: &map[string]any{"api_key": "new-key", "endpoint": "https://b.example"},
	})
	require.NoError(t, err)
	assert.Equal(t, "https://b.example", saved["endpoint"])
}
