package request

import "testing"

func TestCreateGatewayRequest_ValidateSlug(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     CreateGatewayRequest
		wantErr bool
	}{
		{name: "omitted slug is accepted", req: CreateGatewayRequest{Name: "Acme"}},
		{name: "valid slug is accepted", req: CreateGatewayRequest{Name: "Acme", Slug: "acme-prod"}},
		{name: "invalid slug is rejected", req: CreateGatewayRequest{Name: "Acme", Slug: "-bad"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.req.Validate()
			if tt.wantErr && err == nil {
				t.Fatal("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestUpdateGatewayRequest_ValidateSlug(t *testing.T) {
	t.Parallel()
	valid := "acme-prod"
	invalid := "bad_slug"

	if err := (UpdateGatewayRequest{Slug: &valid}).Validate(); err != nil {
		t.Fatalf("valid slug rejected: %v", err)
	}
	if err := (UpdateGatewayRequest{Slug: &invalid}).Validate(); err == nil {
		t.Fatal("expected invalid slug error, got nil")
	}
}
