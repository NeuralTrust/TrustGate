package request

import (
	"testing"

	domain "github.com/NeuralTrust/AgentGateway/pkg/domain/consumer"
)

func strPtr(v string) *string { return &v }

func TestUpdateConsumerRequest_ToType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   *string
		want *domain.Type
	}{
		{"omitted", nil, nil},
		{"empty", strPtr(""), nil},
		{"whitespace", strPtr("   "), nil},
		{"value", strPtr("MCP"), func() *domain.Type { v := domain.Type("MCP"); return &v }()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := UpdateConsumerRequest{Type: tc.in}.ToType()
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("ToType() nilness mismatch: got=%v want=%v", got, tc.want)
			}
			if got != nil && *got != *tc.want {
				t.Fatalf("ToType() = %q, want %q", *got, *tc.want)
			}
		})
	}
}

func TestUpdateConsumerRequest_ToAlgorithm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   *string
		want *string
	}{
		{"omitted", nil, nil},
		{"empty", strPtr(""), nil},
		{"whitespace", strPtr("   "), nil},
		{"value", strPtr("round-robin"), strPtr("round-robin")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := UpdateConsumerRequest{Algorithm: tc.in}.ToAlgorithm()
			if (got == nil) != (tc.want == nil) {
				t.Fatalf("ToAlgorithm() nilness mismatch: got=%v want=%v", got, tc.want)
			}
			if got != nil && *got != *tc.want {
				t.Fatalf("ToAlgorithm() = %q, want %q", *got, *tc.want)
			}
		})
	}
}
