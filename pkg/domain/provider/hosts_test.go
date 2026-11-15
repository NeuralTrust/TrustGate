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

package provider

import "testing"

// TestEveryProviderHasAHostRule fails when a new provider is added without
// saying where its credentials go: a store with allowed destinations would
// otherwise refuse every reference it holds.
func TestEveryProviderHasAHostRule(t *testing.T) {
	derived := map[string]bool{Vertex: true, Bedrock: true, Azure: true, OpenAICompatible: true, Watsonx: true}
	for _, name := range Supported() {
		if DefaultHost(name) == "" && !derived[name] {
			t.Errorf("provider %q has no default host and derives none", name)
		}
	}
}

func TestWatsonxHost(t *testing.T) {
	for _, region := range WatsonxRegions() {
		if got, want := WatsonxHost(region), region+".ml.cloud.ibm.com"; got != want {
			t.Errorf("WatsonxHost(%q) = %q, want %q", region, got, want)
		}
	}
	for _, region := range []string{"", "EU-DE", "eu-de.attacker.example", "ap-south-1", "us-south#"} {
		if got := WatsonxHost(region); got != "" {
			t.Errorf("WatsonxHost(%q) = %q, want no host", region, got)
		}
	}
	if !HonorsBaseURL(Watsonx) {
		t.Error("watsonx calls provider_options.base_url when it is set")
	}
}
