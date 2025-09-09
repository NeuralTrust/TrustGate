package request

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
)

func TestUpstreamRequest_ValidateProviderOptions(t *testing.T) {
	tests := []struct {
		name    string
		request UpstreamRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "OpenAI Responses API with single target should succeed",
			request: UpstreamRequest{
				Name:      "Test Upstream",
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "target1",
						Provider: factory.ProviderOpenAI,
						ProviderOptions: map[string]any{
							"api": "responses",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "OpenAI Responses API with multiple targets should fail",
			request: UpstreamRequest{
				Name:      "Test Upstream",
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "target1",
						Provider: factory.ProviderOpenAI,
						ProviderOptions: map[string]any{
							"api": "responses",
						},
					},
					{
						ID:       "target2",
						Provider: factory.ProviderOpenAI,
						ProviderOptions: map[string]any{
							"api": "responses",
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "cannot perform load balancing: OpenAI Responses API supports only a single target",
		},
		{
			name: "OpenAI Completions API with multiple targets should succeed",
			request: UpstreamRequest{
				Name:      "Test Upstream",
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "target1",
						Provider: factory.ProviderOpenAI,
						ProviderOptions: map[string]any{
							"api": "completions",
						},
					},
					{
						ID:       "target2",
						Provider: factory.ProviderOpenAI,
						ProviderOptions: map[string]any{
							"api": "completions",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "OpenAI Responses API mixed with Completions API should fail",
			request: UpstreamRequest{
				Name:      "Test Upstream",
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "target1",
						Provider: factory.ProviderOpenAI,
						ProviderOptions: map[string]any{
							"api": "responses",
						},
					},
					{
						ID:       "target2",
						Provider: factory.ProviderOpenAI,
						ProviderOptions: map[string]any{
							"api": "completions",
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "cannot perform load balancing: OpenAI Responses API supports only a single target",
		},
		{
			name: "OpenAI provider without api option with multiple targets should succeed",
			request: UpstreamRequest{
				Name:      "Test Upstream",
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "target1",
						Provider: factory.ProviderOpenAI,
					},
					{
						ID:       "target2",
						Provider: factory.ProviderOpenAI,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Non-OpenAI provider with multiple targets should succeed",
			request: UpstreamRequest{
				Name:      "Test Upstream",
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "target1",
						Provider: factory.ProviderGemini,
					},
					{
						ID:       "target2",
						Provider: factory.ProviderGemini,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "OpenAI invalid API value should fail",
			request: UpstreamRequest{
				Name:      "Test Upstream",
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "target1",
						Provider: factory.ProviderOpenAI,
						ProviderOptions: map[string]any{
							"api": "invalid-api",
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "target 0: openai provider_options 'api' field must be 'completions' or 'responses'",
		},
		{
			name: "OpenAI api field not string should fail",
			request: UpstreamRequest{
				Name:      "Test Upstream",
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "target1",
						Provider: factory.ProviderOpenAI,
						ProviderOptions: map[string]any{
							"api": 123,
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "target 0: openai provider_options 'api' field must be a string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("UpstreamRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("UpstreamRequest.Validate() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}
