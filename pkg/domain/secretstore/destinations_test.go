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

package secretstore

import (
	"errors"
	"testing"
)

func TestAllowsDestinations(t *testing.T) {
	t.Parallel()
	s := &Store{Name: "vault", AllowedDestinations: []string{"api.openai.com", "*.amazonaws.com"}}
	for _, hosts := range [][]string{
		{"api.openai.com"},
		{"https://API.OpenAI.com:443/v1"},
		{"api.openai.com."},
		{"bedrock-runtime.eu-west-1.amazonaws.com", "sts.amazonaws.com"},
	} {
		if err := s.AllowsDestinations(hosts); err != nil {
			t.Errorf("%v: %v", hosts, err)
		}
	}
	for _, hosts := range [][]string{
		nil,
		{""},
		{"api.openai.com.attacker.example"},
		{"amazonaws.com"},
		{"evilamazonaws.com"},
		{"api.openai.com", "attacker.example"},
	} {
		if err := s.AllowsDestinations(hosts); !errors.Is(err, ErrDestinationNotAllowed) || ClassOf(err) != ClassDestinationNotAllowed {
			t.Errorf("%v: err = %v, want destination_not_allowed", hosts, err)
		}
	}
	if err := (&Store{Name: "open"}).AllowsDestinations(nil); err != nil {
		t.Errorf("a store without allowed destinations allows any host: %v", err)
	}
}

func TestValidateDestinations(t *testing.T) {
	t.Parallel()
	if err := validateDestinations("s", []string{}); !errors.Is(err, ErrInvalidStore) {
		t.Errorf("an empty list must be refused, not read as absent: %v", err)
	}
	for _, bad := range []string{"https://api.openai.com", "API.openai.com", "api.openai.com:443", "api.openai.com.", "*", "a.*.com", "api.openai.com/v1", ""} {
		if err := validateDestinations("s", []string{bad}); !errors.Is(err, ErrInvalidStore) {
			t.Errorf("%q must be refused: %v", bad, err)
		}
	}
	if err := validateDestinations("s", []string{"api.openai.com", "*.amazonaws.com", "10.0.0.1"}); err != nil {
		t.Errorf("valid list refused: %v", err)
	}
}
