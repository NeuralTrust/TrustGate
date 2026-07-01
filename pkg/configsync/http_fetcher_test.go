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

package configsync

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHTTPFetcher_Fetch(t *testing.T) {
	t.Parallel()

	const (
		token      = "secret-token"
		instanceID = "dp-1"
		body       = "snapshot-bytes"
		etag       = "abc123"
	)

	tests := []struct {
		name            string
		requestETag     string
		status          int
		responseETag    string
		wantRaw         []byte
		wantVersion     string
		wantNotModified bool
		wantErr         bool
	}{
		{
			name:         "200 returns body and etag",
			requestETag:  "",
			status:       http.StatusOK,
			responseETag: `"` + etag + `"`,
			wantRaw:      []byte(body),
			wantVersion:  etag,
		},
		{
			name:            "304 signals not modified",
			requestETag:     etag,
			status:          http.StatusNotModified,
			wantNotModified: true,
		},
		{
			name:        "unexpected status errors",
			requestETag: "",
			status:      http.StatusInternalServerError,
			wantErr:     true,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var gotHeaders http.Header
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeaders = r.Header.Clone()
				if tc.responseETag != "" {
					w.Header().Set(headerETag, tc.responseETag)
				}
				w.WriteHeader(tc.status)
				if tc.status == http.StatusOK {
					_, _ = w.Write([]byte(body))
				}
			}))
			defer srv.Close()

			fetcher := NewHTTPFetcher(srv.URL, token, srv.Client(), instanceID)
			raw, version, notModified, err := fetcher.Fetch(context.Background(), tc.requestETag)

			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			assert.Equal(t, "Bearer "+token, gotHeaders.Get(headerAuthorization))
			assert.Equal(t, instanceID, gotHeaders.Get(headerInstanceID))
			if tc.requestETag != "" {
				assert.Equal(t, tc.requestETag, gotHeaders.Get(headerIfNoneMatch))
				assert.Equal(t, tc.requestETag, gotHeaders.Get(headerAppliedVersion))
			}

			assert.Equal(t, tc.wantNotModified, notModified)
			assert.Equal(t, tc.wantVersion, version)
			assert.Equal(t, tc.wantRaw, raw)
		})
	}
}

func TestHTTPFetcher_RejectsOversizedBody(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set(headerETag, `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(make([]byte, 64))
	}))
	defer srv.Close()

	fetcher := NewHTTPFetcher(srv.URL, "", srv.Client(), "")
	fetcher.maxBytes = 16
	_, _, _, err := fetcher.Fetch(context.Background(), "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds")
}

func TestNewHTTPFetcher_NilClientFallsBack(t *testing.T) {
	t.Parallel()
	fetcher := NewHTTPFetcher("http://example.invalid", "", nil, "")
	assert.Same(t, http.DefaultClient, fetcher.client)
}
