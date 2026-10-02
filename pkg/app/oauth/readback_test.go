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

package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	authdomain "github.com/NeuralTrust/TrustGate/pkg/domain/auth"
	"github.com/stretchr/testify/require"
)

type staticUserInfo struct{ claims map[string]any }

func (f staticUserInfo) Fetch(context.Context, string, string) (map[string]any, error) {
	return f.claims, nil
}

func TestCaptureSubject_UserInfoClaimMustBeAPlainIdentifier(t *testing.T) {
	tests := []struct {
		name    string
		claim   any
		want    string
		wantErr bool
	}{
		{"string", "user-1", "user-1", false},
		{"numeric id", json.Number("583231"), "583231", false},
		{"float id", float64(42), "42", false},
		{"absent claim", nil, "", false},
		{"object is not stringified", map[string]any{"secret": "internal-data"}, "", true},
		{"array is not stringified", []any{"a", "b"}, "", true},
		{"bool is refused", true, "", true},
		{"oversized string", strings.Repeat("a", maxSubjectLen+1), "", true},
		{"control characters", "abc\x00def", "", true},
		{"newline", "abc\ndef", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &authProxy{userinfo: staticUserInfo{claims: map[string]any{"sub": tt.claim}}}
			got, err := p.captureSubject(context.Background(),
				&authdomain.OAuth2Config{UserInfoURL: "https://idp.example/userinfo"},
				map[string]any{"access_token": "tok"})
			if tt.wantErr {
				require.Error(t, err)
				require.NotContains(t, err.Error(), "internal-data")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestIDPTokenCall_ErrorDescriptionIsCappedAndStripped(t *testing.T) {
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error":             "invalid_client",
			"error_description": "line1\r\nSet-Cookie: x=1\x00" + strings.Repeat("A", 5000),
		})
	}))
	defer idp.Close()

	tr := newIDPTransport(idp.Client(), nil)
	_, err := tr.tokenCall(context.Background(), idp.URL, url.Values{})
	var oe *OAuthError
	require.ErrorAs(t, err, &oe)
	require.Equal(t, "invalid_client", oe.Code, "the code legit providers need is kept")
	require.LessOrEqual(t, len(oe.Description), maxUpstreamErrorDescLen)
	require.NotContains(t, oe.Description, "\r")
	require.NotContains(t, oe.Description, "\n")
	require.NotContains(t, oe.Description, "\x00")
}
