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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// credentialPlugin is a fakePlugin that implements CredentialSettings, so the
// tests can cover both sides of the RUN-1646 opt-in without touching a real
// plugin.
type credentialPlugin struct {
	fakePlugin
	paths []string
}

func (p *credentialPlugin) CredentialPaths() []string { return p.paths }

func preRequestFake(name string) fakePlugin {
	return fakePlugin{name: name, stages: []policy.Stage{policy.StagePreRequest}, result: &Result{}}
}

func TestPluginCredentialPaths_PluginNotOptedIn(t *testing.T) {
	reg := NewRegistry()
	plain := preRequestFake("plain")
	require.NoError(t, reg.Register(&plain))

	got := PluginCredentialPaths(reg, "plain")
	assert.Nil(t, got, "a plugin that never implements CredentialSettings must report no credential paths")
}

func TestPluginCredentialPaths_PluginOptedIn(t *testing.T) {
	reg := NewRegistry()
	withCreds := &credentialPlugin{fakePlugin: preRequestFake("with_creds"), paths: []string{"credentials.api_key"}}
	require.NoError(t, reg.Register(withCreds))

	got := PluginCredentialPaths(reg, "with_creds")
	assert.Equal(t, []string{"credentials.api_key"}, got)
}

func TestPluginCredentialPaths_UnknownSlugOrNilRegistry(t *testing.T) {
	reg := NewRegistry()
	assert.Nil(t, PluginCredentialPaths(reg, "does_not_exist"))
	assert.Nil(t, PluginCredentialPaths(nil, "anything"))
}
