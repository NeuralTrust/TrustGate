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

// Package gcpkey validates tenant-supplied Google service-account key JSON.
//
// The key is attacker-controlled input: Google's client libraries read the
// endpoint they POST the signed JWT assertion to from the key's own token_uri.
// Left unchecked, a tenant could aim the gateway at any URL it can reach
// (cluster services, the metadata server). Validate rejects such keys at write
// time and TokenURL is what the token request is pinned to regardless.
package gcpkey

import (
	"encoding/json"
	"fmt"
	"strings"
)

const (
	// TokenURL is the only endpoint a token request built from a tenant key is
	// ever sent to.
	TokenURL = "https://oauth2.googleapis.com/token" // #nosec G101 -- public endpoint, not a credential

	serviceAccountType = "service_account"
	defaultUniverse    = "googleapis.com"
)

// allowedTokenURIs are the token_uri values Google itself writes into key files.
// The legacy form appears in older downloaded keys. They are accepted so
// those keys keep working, but the request is still sent to TokenURL.
var allowedTokenURIs = map[string]struct{}{
	TokenURL: {},
	"https://accounts.google.com/o/oauth2/token": {},
}

type keyFile struct {
	Type           string `json:"type"`
	TokenURI       string `json:"token_uri"`
	UniverseDomain string `json:"universe_domain"`
}

// Validate checks that raw is a service-account key whose endpoint-bearing
// fields are Google's. Errors name the offending field and never echo the
// value, because the JSON is a credential.
func Validate(raw string) error {
	var k keyFile
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &k); err != nil {
		return fmt.Errorf("gcp service account: must be a JSON object")
	}
	if k.Type != serviceAccountType {
		return fmt.Errorf("gcp service account: type must be %q", serviceAccountType)
	}
	if k.TokenURI != "" {
		if _, ok := allowedTokenURIs[k.TokenURI]; !ok {
			return fmt.Errorf("gcp service account: token_uri must be a Google OAuth token endpoint")
		}
	}
	if k.UniverseDomain != "" && k.UniverseDomain != defaultUniverse {
		return fmt.Errorf("gcp service account: universe_domain must be %q", defaultUniverse)
	}
	return nil
}
