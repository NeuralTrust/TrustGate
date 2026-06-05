package secret_test

import (
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/common/secret"
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
	if got := secret.Mask("secret-value"); got != secret.Redacted {
		t.Fatalf("Mask(set) = %q, want %q", got, secret.Redacted)
	}
}
