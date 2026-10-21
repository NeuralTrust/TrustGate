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

package request_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/configsync/request"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/stretchr/testify/require"
)

func TestRevokeTokensRequest_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "empty object", body: `{}`, wantErr: true},
		{name: "empty jtis", body: `{"jtis":[]}`, wantErr: true},
		{name: "empty jti entry", body: `{"jtis":[""]}`, wantErr: true},
		{name: "zero issued_before", body: `{"issued_before":0}`, wantErr: true},
		{name: "negative issued_before", body: `{"issued_before":-1}`, wantErr: true},
		{name: "jtis only", body: `{"jtis":["a1"]}`},
		{name: "issued_before only", body: `{"issued_before":1000}`},
		{name: "jtis and issued_before", body: `{"jtis":["a1"],"issued_before":1000}`},
		{name: "100 jtis is allowed", body: `{"jtis":[` + repeatJTI(100) + `]}`},
		{name: "101 jtis is rejected", body: `{"jtis":[` + repeatJTI(101) + `]}`, wantErr: true},
		{name: "128 byte jti is allowed", body: `{"jtis":["` + strings.Repeat("x", 128) + `"]}`},
		{name: "129 byte jti is rejected", body: `{"jtis":["` + strings.Repeat("x", 129) + `"]}`, wantErr: true},
		{name: "jti with a NUL byte is rejected", body: `{"jtis":["a\u0000b"]}`, wantErr: true},
		{name: "jti with a newline is rejected", body: `{"jtis":["a\nb"]}`, wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var req request.RevokeTokensRequest
			require.NoError(t, json.Unmarshal([]byte(tc.body), &req))
			err := req.Validate()
			if !tc.wantErr {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			require.ErrorIs(t, err, commonerrors.ErrValidation)
		})
	}
}

func repeatJTI(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf(`"j%d"`, i)
	}
	return strings.Join(parts, ",")
}
