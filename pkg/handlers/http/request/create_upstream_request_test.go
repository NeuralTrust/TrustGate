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
			name: "OpenAI Responses API with multiple targets should succeed",
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
			wantErr: false,
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
			name: "OpenAI Responses API mixed with Completions API should succeed",
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
			wantErr: false,
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
						Provider: factory.ProviderGoogle,
					},
					{
						ID:       "target2",
						Provider: factory.ProviderGoogle,
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

func TestUpstreamRequest_ValidateVertexProviderOptions(t *testing.T) {
	tests := []struct {
		name    string
		request UpstreamRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "Vertex with valid options should succeed",
			request: UpstreamRequest{
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "t1",
						Provider: factory.ProviderVertex,
						ProviderOptions: map[string]any{
							"project":  "my-project",
							"location": "us-central1",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Vertex with version option should succeed",
			request: UpstreamRequest{
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "t1",
						Provider: factory.ProviderVertex,
						ProviderOptions: map[string]any{
							"project":  "my-project",
							"location": "us-central1",
							"version":  "v1beta1",
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Vertex missing provider_options should fail",
			request: UpstreamRequest{
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "t1",
						Provider: factory.ProviderVertex,
					},
				},
			},
			wantErr: true,
			errMsg:  "target 0: vertex provider requires provider_options with 'project' and 'location'",
		},
		{
			name: "Vertex missing project should fail",
			request: UpstreamRequest{
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "t1",
						Provider: factory.ProviderVertex,
						ProviderOptions: map[string]any{
							"location": "us-central1",
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "target 0: vertex provider_options.project is required",
		},
		{
			name: "Vertex missing location should fail",
			request: UpstreamRequest{
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "t1",
						Provider: factory.ProviderVertex,
						ProviderOptions: map[string]any{
							"project": "p",
						},
					},
				},
			},
			wantErr: true,
			errMsg:  "target 0: vertex provider_options.location is required",
		},
		{
			name: "Vertex unknown option key should fail",
			request: UpstreamRequest{
				Algorithm: "round-robin",
				Targets: []TargetRequest{
					{
						ID:       "t1",
						Provider: factory.ProviderVertex,
						ProviderOptions: map[string]any{
							"project":  "p",
							"location": "l",
							"unknown":  "x",
						},
					},
				},
			},
			wantErr: true,
			errMsg:  `target 0: vertex provider_options contains unknown key "unknown" (allowed: project, location, version)`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("Validate() error = %q, want %q", err.Error(), tt.errMsg)
			}
		})
	}
}
