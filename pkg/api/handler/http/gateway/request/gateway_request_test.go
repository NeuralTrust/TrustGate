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

package request

import "testing"

func TestCreateGatewayRequest_ValidateSlug(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     CreateGatewayRequest
		wantErr bool
	}{
		{name: "empty slug is accepted (auto-generated)", req: CreateGatewayRequest{Slug: ""}},
		{name: "valid slug is accepted", req: CreateGatewayRequest{Slug: "acme-prod"}},
		{name: "invalid slug is rejected", req: CreateGatewayRequest{Slug: "-bad"}, wantErr: true},
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
	empty := ""

	if err := (UpdateGatewayRequest{Slug: &valid}).Validate(); err != nil {
		t.Fatalf("valid slug rejected: %v", err)
	}
	if err := (UpdateGatewayRequest{Slug: &invalid}).Validate(); err == nil {
		t.Fatal("expected invalid slug error, got nil")
	}
	if err := (UpdateGatewayRequest{Slug: &empty}).Validate(); err == nil {
		t.Fatal("expected empty slug error, got nil")
	}
}
