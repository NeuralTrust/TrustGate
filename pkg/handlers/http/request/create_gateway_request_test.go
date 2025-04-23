package request

import (
	"testing"
)

func TestCreateGatewayRequest_Validate(t *testing.T) {
	tests := []struct {
		name    string
		request CreateGatewayRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "Valid HeaderMapping with conversation_id",
			request: CreateGatewayRequest{
				Telemetry: &TelemetryRequest{
					HeaderMapping: map[string]string{
						"conversation_id": "X-CONVERSATION-ID",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid HeaderMapping with interaction_id",
			request: CreateGatewayRequest{
				Telemetry: &TelemetryRequest{
					HeaderMapping: map[string]string{
						"interaction_id": "X-INTERACTION-ID",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid HeaderMapping with both keys",
			request: CreateGatewayRequest{
				Telemetry: &TelemetryRequest{
					HeaderMapping: map[string]string{
						"conversation_id": "X-CONVERSATION-ID",
						"interaction_id": "X-INTERACTION-ID",
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid HeaderMapping with unsupported key",
			request: CreateGatewayRequest{
				Telemetry: &TelemetryRequest{
					HeaderMapping: map[string]string{
						"unsupported_key": "X-UNSUPPORTED",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid key in header_mapping: unsupported_key. Only 'conversation_id' and 'interaction_id' are allowed",
		},
		{
			name: "Invalid HeaderMapping with mix of valid and invalid keys",
			request: CreateGatewayRequest{
				Telemetry: &TelemetryRequest{
					HeaderMapping: map[string]string{
						"conversation_id": "X-CONVERSATION-ID",
						"unsupported_key": "X-UNSUPPORTED",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid key in header_mapping: unsupported_key. Only 'conversation_id' and 'interaction_id' are allowed",
		},
		{
			name: "Nil Telemetry",
			request: CreateGatewayRequest{
				Telemetry: nil,
			},
			wantErr: false,
		},
		{
			name: "Nil HeaderMapping",
			request: CreateGatewayRequest{
				Telemetry: &TelemetryRequest{
					HeaderMapping: nil,
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.request.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("CreateGatewayRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err.Error() != tt.errMsg {
				t.Errorf("CreateGatewayRequest.Validate() error message = %v, want %v", err.Error(), tt.errMsg)
			}
		})
	}
}
