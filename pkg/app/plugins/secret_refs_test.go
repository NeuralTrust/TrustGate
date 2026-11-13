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

import "testing"

func TestPlanSettingsNeverCarryASecretReference(t *testing.T) {
	t.Parallel()
	p := &credentialPlugin{fakePlugin: preRequestFake("guard"), paths: []string{"credentials.secret_access_key", "api_key"}}
	settings := map[string]any{
		"api_key":     "sk-live",
		"credentials": map[string]any{"secret_access_key": "secret://vault/aws#sk", "region": "eu-west-1"},
	}
	out := withoutSecretReferences(p, settings)
	if got := out["credentials"].(map[string]any)["secret_access_key"]; got != "" {
		t.Fatalf("secret_access_key = %v; an unresolved reference must be emptied", got)
	}
	if out["api_key"] != "sk-live" || out["credentials"].(map[string]any)["region"] != "eu-west-1" {
		t.Fatalf("other settings must be kept: %v", out)
	}
	if settings["credentials"].(map[string]any)["secret_access_key"] != "secret://vault/aws#sk" {
		t.Fatal("the policy's own settings must not be modified")
	}
	plain := map[string]any{"api_key": "sk-live"}
	if got := withoutSecretReferences(p, plain); got["api_key"] != "sk-live" {
		t.Fatal("settings without references pass through")
	}
}
