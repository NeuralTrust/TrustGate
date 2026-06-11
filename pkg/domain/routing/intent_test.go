package routing_test

import (
	"errors"
	"testing"

	"github.com/NeuralTrust/AgentGateway/pkg/domain/routing"
)

func TestParseModelRef(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		ref     string
		want    routing.RoutingIntent
		wantErr error
	}{
		{"empty is zero intent", "", routing.RoutingIntent{}, nil},
		{"whitespace is zero intent", "   ", routing.RoutingIntent{}, nil},
		{"qualified provider model", "openai/gpt-5", routing.RoutingIntent{Provider: "openai", Model: "gpt-5"}, nil},
		{"provider is lowercased", "OpenAI/gpt-5", routing.RoutingIntent{Provider: "openai", Model: "gpt-5"}, nil},
		{"model keeps nested slashes", "openrouter/meta-llama/llama-3-70b", routing.RoutingIntent{Provider: "openrouter", Model: "meta-llama/llama-3-70b"}, nil},
		{"pool alias", "pool:fast-chat", routing.RoutingIntent{PoolAlias: "fast-chat"}, nil},
		{"pool prefix is case insensitive", "POOL:fast-chat", routing.RoutingIntent{PoolAlias: "fast-chat"}, nil},
		{"short model", "gpt-5", routing.RoutingIntent{Model: "gpt-5"}, nil},
		{"bedrock arn stays a native model", "arn:aws:bedrock:eu-west-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-v1:0",
			routing.RoutingIntent{Model: "arn:aws:bedrock:eu-west-1:123456789012:inference-profile/eu.anthropic.claude-sonnet-4-v1:0"}, nil},
		{"non-identifier provider stays a native model", "weird provider/model-x",
			routing.RoutingIntent{Model: "weird provider/model-x"}, nil},
		{"empty pool alias", "pool:", routing.RoutingIntent{}, routing.ErrInvalidModelRef},
		{"pool alias with slash", "pool:a/b", routing.RoutingIntent{}, routing.ErrInvalidModelRef},
		{"empty provider", "/gpt-5", routing.RoutingIntent{}, routing.ErrInvalidModelRef},
		{"empty model", "openai/", routing.RoutingIntent{}, routing.ErrInvalidModelRef},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := routing.ParseModelRef(tc.ref)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("expected %v, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected %+v, got %+v", tc.want, got)
			}
		})
	}
}

func TestRoutingIntentPredicates(t *testing.T) {
	t.Parallel()
	if !(routing.RoutingIntent{}).IsZero() {
		t.Fatal("empty intent must be zero")
	}
	qualified := routing.RoutingIntent{Provider: "openai", Model: "gpt-5"}
	if !qualified.IsQualified() || qualified.IsShortModel() || qualified.IsPool() {
		t.Fatal("qualified intent predicates mismatch")
	}
	short := routing.RoutingIntent{Model: "gpt-5"}
	if !short.IsShortModel() || short.IsQualified() {
		t.Fatal("short intent predicates mismatch")
	}
	pool := routing.RoutingIntent{PoolAlias: "fast"}
	if !pool.IsPool() || pool.IsZero() {
		t.Fatal("pool intent predicates mismatch")
	}
}
