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

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func TestSetOwnerGroups(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC)

	owned := &Auth{OwnerID: "alice"}
	if err := owned.SetOwnerGroups([]string{" sre ", "engineering", "sre", ""}, now); err != nil {
		t.Fatalf("SetOwnerGroups: %v", err)
	}
	if want := []string{"engineering", "sre"}; !slices.Equal(owned.OwnerGroups, want) {
		t.Fatalf("groups = %v, want %v", owned.OwnerGroups, want)
	}
	if !owned.UpdatedAt.Equal(now) {
		t.Fatalf("updated_at = %v, want %v", owned.UpdatedAt, now)
	}
	if err := owned.SetOwnerGroups(nil, now); err != nil || owned.OwnerGroups != nil {
		t.Fatalf("clearing: groups = %v, err = %v", owned.OwnerGroups, err)
	}

	application := &Auth{}
	if err := application.SetOwnerGroups([]string{"sre"}, now); !errors.Is(err, ErrApplicationKey) {
		t.Fatalf("application key: err = %v, want ErrApplicationKey", err)
	}
}

func TestNormalizeOwnerGroups_RefusesPastTheBounds(t *testing.T) {
	t.Parallel()
	many := make([]string, MaxOwnerGroups+1)
	for i := range many {
		many[i] = fmt.Sprintf("group-%d", i)
	}
	for name, groups := range map[string][]string{
		"a name too long": {strings.Repeat("g", MaxOwnerGroupLength+1)},
		"too many groups": many,
	} {
		if _, err := NormalizeOwnerGroups(groups); !errors.Is(err, commonerrors.ErrValidation) {
			t.Errorf("%s: err = %v, want a validation error", name, err)
		}
	}
	if _, err := NormalizeOwnerGroups(many[:MaxOwnerGroups]); err != nil {
		t.Errorf("at the bound: %v", err)
	}
}

func TestNormalizeOwnerEmail(t *testing.T) {
	for _, tc := range []struct {
		in, want string
		ok       bool
	}{
		{" ada@acme.test ", "ada@acme.test", true},
		{"", "", true},
		{"not-an-email", "", false},
		{"@acme.test", "", false},
		{"ada@", "", false},
		{"ada lovelace@acme.test", "", false},
		{strings.Repeat("a", 320) + "@acme.test", "", false},
	} {
		got, err := NormalizeOwnerEmail(tc.in)
		if (err == nil) != tc.ok || got != tc.want {
			t.Fatalf("NormalizeOwnerEmail(%q) = %q, %v", tc.in, got, err)
		}
	}
}

func TestSetOwnerEmail_OnlyOnAPersonalKey(t *testing.T) {
	app := &Auth{}
	if err := app.SetOwnerEmail("ada@acme.test", time.Now()); err != ErrApplicationKey {
		t.Fatalf("err = %v, want ErrApplicationKey", err)
	}
	owned := &Auth{OwnerID: "ada"}
	if err := owned.SetOwnerEmail("ada@acme.test", time.Now()); err != nil || owned.OwnerEmail != "ada@acme.test" {
		t.Fatalf("owned = %+v, %v", owned, err)
	}
}
