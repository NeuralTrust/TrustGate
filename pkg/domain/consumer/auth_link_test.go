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

package consumer

import (
	"errors"
	"math"
	"testing"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
)

func TestGrantLevel(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in       string
		wantRank int
		wantErr  bool
	}{
		{in: "user", wantRank: 0},
		{in: "group", wantRank: 1},
		{in: "all", wantRank: 2},
		{in: "", wantRank: 3, wantErr: true},
		{in: "team", wantRank: 3, wantErr: true},
		{in: "User", wantRank: 3, wantErr: true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			level, err := ParseGrantLevel(tc.in)
			if tc.wantErr != errors.Is(err, ErrInvalidAuthLink) {
				t.Fatalf("ParseGrantLevel(%q) error = %v, wantErr %v", tc.in, err, tc.wantErr)
			}
			if !tc.wantErr && level != GrantLevel(tc.in) {
				t.Fatalf("ParseGrantLevel(%q) = %q", tc.in, level)
			}
			if got := GrantLevel(tc.in).Rank(); got != tc.wantRank {
				t.Fatalf("Rank(%q) = %d, want %d", tc.in, got, tc.wantRank)
			}
		})
	}
}

func TestAuthLinkValidate(t *testing.T) {
	t.Parallel()
	grantedAt := time.Date(2026, time.October, 1, 9, 0, 0, 0, time.UTC)
	for name, tc := range map[string]struct {
		link    AuthLink
		wantErr bool
	}{
		"group with default priority": {link: AuthLink{Level: GrantLevelGroup, Priority: DefaultGrantPriority, GrantedAt: grantedAt}},
		"user with priority zero":     {link: AuthLink{Level: GrantLevelUser, GrantedAt: grantedAt}},
		"unknown level":               {link: AuthLink{Level: "team", Priority: 1, GrantedAt: grantedAt}, wantErr: true},
		"missing level":               {link: AuthLink{Priority: 1, GrantedAt: grantedAt}, wantErr: true},
		"priority below zero":         {link: AuthLink{Level: GrantLevelAll, Priority: -1, GrantedAt: grantedAt}, wantErr: true},
		"priority at int32 max":       {link: AuthLink{Level: GrantLevelAll, Priority: math.MaxInt32, GrantedAt: grantedAt}},
		"priority above int32 max":    {link: AuthLink{Level: GrantLevelAll, Priority: math.MaxInt32 + 1, GrantedAt: grantedAt}, wantErr: true},
		"zero granted_at":             {link: AuthLink{Level: GrantLevelAll, Priority: 1}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := tc.link.Validate()
			if (!tc.wantErr && err != nil) || (tc.wantErr && (!errors.Is(err, ErrInvalidAuthLink) || !errors.Is(err, commonerrors.ErrValidation))) {
				t.Fatalf("Validate() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestConsumerValidateAuthLink(t *testing.T) {
	t.Parallel()
	valid := &AuthLink{Level: GrantLevelGroup, Priority: DefaultGrantPriority, GrantedAt: time.Date(2026, time.October, 1, 9, 0, 0, 0, time.UTC)}
	for name, tc := range map[string]struct {
		audience Audience
		link     *AuthLink
		wantErr  bool
	}{
		"application without link":      {},
		"application with a link":       {link: valid, wantErr: true},
		"personal with a valid link":    {audience: AudiencePersonal, link: valid},
		"personal without link":         {audience: AudiencePersonal, wantErr: true},
		"personal with an invalid link": {audience: AudiencePersonal, link: &AuthLink{Level: GrantLevelUser}, wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := (&Consumer{Type: TypeLLM, Audience: tc.audience}).ValidateAuthLink(tc.link)
			if (!tc.wantErr && err != nil) || (tc.wantErr && (!errors.Is(err, ErrInvalidAuthLink) || !errors.Is(err, commonerrors.ErrValidation))) {
				t.Fatalf("ValidateAuthLink() = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}
