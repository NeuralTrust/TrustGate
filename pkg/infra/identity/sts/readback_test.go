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

package sts

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTokenClient_ErrorDescriptionIsCappedAndStripped(t *testing.T) {
	t.Parallel()
	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_target","error_description":"a\r\nb\u0000` + strings.Repeat("Z", 4000) + `"}`))
	}))
	defer idp.Close()

	_, err := NewTokenClient(idp.Client()).tokenCall(context.Background(), idp.URL, url.Values{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid_target")
	require.Less(t, len(err.Error()), 400)
	require.False(t, strings.ContainsAny(err.Error(), "\r\n\x00"))
}
