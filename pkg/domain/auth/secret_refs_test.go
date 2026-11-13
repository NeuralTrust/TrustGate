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

package auth

import "testing"

func TestExchangeCredentialsRefuseAnUnresolvedReference(t *testing.T) {
	t.Parallel()
	for _, c := range []*OAuth2Config{
		{ExchangeClientID: "x", ExchangeClientSecret: "secret://vault/idp#x"},
		{ClientID: "c", ClientSecret: "SECRET://vault/idp#c"},
	} {
		if _, _, ok := c.ExchangeCredentials(); ok {
			t.Fatalf("%+v: an exchange must never be signed with a reference", c)
		}
	}
	if id, secret, ok := (&OAuth2Config{ClientID: "c", ClientSecret: "real"}).ExchangeCredentials(); !ok || id != "c" || secret != "real" {
		t.Fatal("a literal secret is still used")
	}
}
