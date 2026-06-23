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

package request

import "testing"

func TestConfigRequestToDomainMapsOAuth2SessionFields(t *testing.T) {
	req := ConfigRequest{
		OAuth2: &OAuth2ConfigRequest{
			Issuer:       "https://github.com",
			Audiences:    []string{"mcp"},
			ClientID:     "client",
			SessionMode:  true,
			UserInfoURL:  "https://api.github.com/user",
			SubjectClaim: "id",
		},
	}

	got := req.ToDomain()

	if got.OAuth2 == nil {
		t.Fatal("expected oauth2 config to be mapped")
	}
	if !got.OAuth2.SessionMode {
		t.Error("session_mode not mapped to domain")
	}
	if got.OAuth2.UserInfoURL != "https://api.github.com/user" {
		t.Errorf("userinfo_url not mapped: got %q", got.OAuth2.UserInfoURL)
	}
	if got.OAuth2.SubjectClaim != "id" {
		t.Errorf("subject_claim not mapped: got %q", got.OAuth2.SubjectClaim)
	}
}
