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
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
)

func TestAudience(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		in       string
		want     Audience
		wantName Audience
		wantErr  bool
	}{
		{in: "", want: "", wantName: AudienceApplication},
		{in: "application", want: "", wantName: AudienceApplication},
		{in: "personal", want: AudiencePersonal, wantName: AudiencePersonal},
		{in: "team", wantErr: true},
		{in: "Personal", wantErr: true},
	} {
		t.Run(tc.in, func(t *testing.T) {
			t.Parallel()
			parsed, parseErr := ParseAudience(tc.in)
			created, newErr := New(CreateParams{GatewayID: ids.New[ids.GatewayKind](), Name: "chat", Type: TypeLLM, Audience: Audience(tc.in)})
			if tc.wantErr {
				if !errors.Is(parseErr, ErrInvalidAudience) || !errors.Is(newErr, ErrInvalidAudience) {
					t.Fatalf("errors = %v, %v; want ErrInvalidAudience", parseErr, newErr)
				}
				return
			}
			if parseErr != nil || newErr != nil {
				t.Fatalf("errors = %v, %v", parseErr, newErr)
			}
			rehydrated := Rehydrate(RehydrateParams{Audience: Audience(tc.in)})
			if parsed != tc.want || created.Audience != tc.want || rehydrated.Audience != tc.want {
				t.Fatalf("parsed %q, created %q, rehydrated %q; want %q", parsed, created.Audience, rehydrated.Audience, tc.want)
			}
			if created.AudienceName() != tc.wantName || created.IsPersonal() != (tc.want == AudiencePersonal) {
				t.Fatalf("AudienceName() = %q, IsPersonal() = %v", created.AudienceName(), created.IsPersonal())
			}
		})
	}
}
