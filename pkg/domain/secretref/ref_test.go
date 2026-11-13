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

package secretref_test

import (
	"errors"
	"strings"
	"testing"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
)

func TestParseValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		in   string
		want secretref.Ref
	}{
		{"secret://aws/prod/llm/anthropic?version=AWSPREVIOUS#key", secretref.Ref{Store: "aws", Path: "prod/llm/anthropic", Version: "AWSPREVIOUS", Field: "key"}},
		{"secret://corp-vault/ai-gateway/openai#api_key", secretref.Ref{Store: "corp-vault", Path: "ai-gateway/openai", Field: "api_key"}},
		{"secret://env/TG_SECRET_OPENAI", secretref.Ref{Store: "env", Path: "TG_SECRET_OPENAI"}},
		{"secret://Corp_Vault/a", secretref.Ref{Store: "corp_vault", Path: "a"}},
		{"secret://k8s/llm-keys/openai%20key#a%23b", secretref.Ref{Store: "k8s", Path: "llm-keys/openai key", Field: "a#b"}},
		{"secret://gcp/projects/p/secrets/s?version=3", secretref.Ref{Store: "gcp", Path: "projects/p/secrets/s", Version: "3"}},
		{"secret://aws/arn:aws:secretsmanager:eu-west-1:1:secret:prod", secretref.Ref{Store: "aws", Path: "arn:aws:secretsmanager:eu-west-1:1:secret:prod"}},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			t.Parallel()
			got, ok, err := secretref.Parse(tt.in)
			if err != nil || !ok {
				t.Fatalf("Parse(%q) = ok %v, err %v", tt.in, ok, err)
			}
			if got != tt.want {
				t.Fatalf("Parse(%q) = %+v, want %+v", tt.in, got, tt.want)
			}
			again, ok, err := secretref.Parse(got.String())
			if err != nil || !ok || again != got {
				t.Fatalf("Parse(String()) = %+v, %v, %v; want %+v", again, ok, err, got)
			}
		})
	}
}

func TestParseLiteral(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"", "sk-live-123", "secret:/x/y", "secrets://x/y", "https://secret://x", "Bearer secret://x/y"} {
		ref, ok, err := secretref.Parse(in)
		if ok || err != nil || ref != (secretref.Ref{}) {
			t.Errorf("Parse(%q) = %+v, %v, %v; want a literal", in, ref, ok, err)
		}
		if secretref.IsRef(in) {
			t.Errorf("IsRef(%q) = true", in)
		}
	}
}

func TestParseInvalid(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"no path":             "secret://corp-vault",
		"empty path":          "secret://corp-vault/",
		"empty segment":       "secret://corp-vault/a//b",
		"trailing slash":      "secret://corp-vault/a/",
		"dot dot":             "secret://k8s/../../etc/passwd",
		"single dot":          "secret://k8s/./a",
		"encoded dot dot":     "secret://k8s/%2e%2e/etc/passwd",
		"encoded slash":       "secret://k8s/llm%2F..%2F..%2Fetc/passwd",
		"encoded backslash":   "secret://k8s/a%5Cb",
		"encoded NUL":         "secret://k8s/a%00b",
		"bad escape":          "secret://k8s/a%zz",
		"empty store":         "secret:///a",
		"bad store":           "secret://-vault/a",
		"store too long":      "secret://" + strings.Repeat("a", 64) + "/a",
		"store with dot":      "secret://corp.vault/a",
		"unknown query":       "secret://aws/a?ttl=5m",
		"two queries":         "secret://aws/a?version=1&version=2",
		"empty version":       "secret://aws/a?version=",
		"empty field":         "secret://aws/a#",
		"version after field": "secret://aws/a#api_key?version=3",
		"two fields":          "secret://aws/a#k#v",
		"leading space":       " secret://aws/a",
		"trailing newline":    "secret://aws/a\n",
		"upper-case scheme":   "SECRET://aws/a",
		"too long":            "secret://aws/" + strings.Repeat("a", secretref.MaxLength),
		"scheme only":         "secret://",
		"field encoded NUL":   "secret://aws/a#%00",
		"version encoded NUL": "secret://aws/a?version=%00",
		"encoded newline":     "secret://aws/a%0Ab",
		"raw tab":             "secret://aws/a\tb",
		"field DEL":           "secret://aws/a#%7F",
	}
	for name, in := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if !secretref.IsRef(in) {
				t.Fatalf("IsRef(%q) = false; every reference-shaped value must be treated as a reference", in)
			}
			_, ok, err := secretref.Parse(in)
			if !ok {
				t.Fatalf("Parse(%q) returned a literal", in)
			}
			if !errors.Is(err, secretref.ErrInvalidReference) || !errors.Is(err, commonerrors.ErrValidation) {
				t.Fatalf("Parse(%q) err = %v, want ErrInvalidReference", in, err)
			}
		})
	}
}

func TestContainsRef(t *testing.T) {
	t.Parallel()
	for _, in := range []string{"Bearer secret://corp-vault/ai/x", "token=SECRET://a/b", "secret://a/b"} {
		if !secretref.ContainsRef(in) {
			t.Errorf("ContainsRef(%q) = false", in)
		}
	}
	for _, in := range []string{"Bearer sk-live", "secret:/a", ""} {
		if secretref.ContainsRef(in) {
			t.Errorf("ContainsRef(%q) = true", in)
		}
	}
}

func TestValidStoreName(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]bool{"corp-vault": true, "a": true, "k8s_2": true, "": false, "-a": false, "Corp": false, "a.b": false} {
		if got := secretref.ValidStoreName(name); got != want {
			t.Errorf("ValidStoreName(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestPayloadKeyIgnoresField(t *testing.T) {
	t.Parallel()
	a := secretref.Ref{Store: "s", Path: "p", Field: "a"}
	b := secretref.Ref{Store: "s", Path: "p", Field: "b"}
	if a.PayloadKey() != b.PayloadKey() {
		t.Fatal("references to the same payload must share a key")
	}
	pathVersion := secretref.Ref{Store: "s", Path: "x|y", Version: "z"}
	split := secretref.Ref{Store: "s", Path: "x", Version: "y|z"}
	if pathVersion.PayloadKey() == split.PayloadKey() {
		t.Fatal("different payloads must not share a key")
	}
}

func FuzzParse(f *testing.F) {
	for _, seed := range []string{
		"secret://corp-vault/ai-gateway/openai#api_key",
		"secret://aws/prod/llm/anthropic?version=AWSPREVIOUS#key",
		"secret://corp-vault",
		"secret://k8s/%2e%2e/etc/passwd",
		"secret://k8s/llm%2F..%2F..%2Fetc/passwd",
		"secret://a/b%23c?version=x%3Dy#f%3Fg",
		" SECRET://a/b",
		"sk-live-123",
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, in string) {
		ref, ok, err := secretref.Parse(in)
		if secretref.IsRef(in) != ok {
			t.Fatalf("IsRef and Parse disagree on %q", in)
		}
		if !ok {
			if err != nil {
				t.Fatalf("literal %q returned an error", in)
			}
			return
		}
		if err != nil {
			return
		}
		if len(in) > secretref.MaxLength {
			t.Fatalf("accepted %d bytes", len(in))
		}
		for _, segment := range ref.Segments() {
			if segment == "" || segment == "." || segment == ".." || strings.ContainsAny(segment, "/\\\x00\n\r") {
				t.Fatalf("accepted segment %q from %q", segment, in)
			}
		}
		if len(ref.String()) > secretref.MaxLength {
			return
		}
		again, ok, err := secretref.Parse(ref.String())
		if err != nil || !ok || again != ref {
			t.Fatalf("round trip of %q: %+v -> %q -> %+v, %v", in, ref, ref.String(), again, err)
		}
	})
}
