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

package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	infraoauth "github.com/NeuralTrust/TrustGate/pkg/infra/oauth"
)

func TestUserInfoClientPreservesIntegerIDsAsJSONNumber(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer gho_token" {
			t.Errorf("unexpected auth header: %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":97445496,"login":"octocat"}`))
	}))
	defer srv.Close()

	client := infraoauth.NewUserInfoClient(srv.Client())
	info, err := client.Fetch(context.Background(), srv.URL, "gho_token")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	num, ok := info["id"].(json.Number)
	if !ok {
		t.Fatalf("expected id to decode as json.Number, got %T (%v)", info["id"], info["id"])
	}
	if num.String() != "97445496" {
		t.Fatalf("expected exact integer id, got %q", num.String())
	}
}
