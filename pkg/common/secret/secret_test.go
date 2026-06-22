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

package secret_test

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
)

func TestResolve(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		incoming string
		existing string
		want     string
	}{
		{name: "empty keeps existing", incoming: "", existing: "stored", want: "stored"},
		{name: "redacted keeps existing", incoming: secret.Redacted, existing: "stored", want: "stored"},
		{name: "masked tail keeps existing", incoming: secret.Redacted + "1234", existing: "stored", want: "stored"},
		{name: "new value replaces", incoming: "fresh", existing: "stored", want: "fresh"},
		{name: "new value with no existing", incoming: "fresh", existing: "", want: "fresh"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := secret.Resolve(tc.incoming, tc.existing); got != tc.want {
				t.Fatalf("Resolve(%q, %q) = %q, want %q", tc.incoming, tc.existing, got, tc.want)
			}
		})
	}
}

func TestMask(t *testing.T) {
	t.Parallel()
	if got := secret.Mask(""); got != "" {
		t.Fatalf("Mask(empty) = %q, want empty", got)
	}
	if got := secret.Mask("short"); got != secret.Redacted {
		t.Fatalf("Mask(short) = %q, want %q (no tail for short secrets)", got, secret.Redacted)
	}
	got := secret.Mask("sk-supersecretvalue1234")
	if got != secret.Redacted+"1234" {
		t.Fatalf("Mask(long) = %q, want %q", got, secret.Redacted+"1234")
	}
	if !secret.IsMasked(got) {
		t.Fatalf("IsMasked(%q) = false, want true", got)
	}
	if secret.IsMasked("sk-real-secret") {
		t.Fatal("IsMasked(real secret) = true, want false")
	}
}
