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

package oracle

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewOracleClient(t *testing.T) {
	assert.NotNil(t, NewOracleClient())
}

func TestCompletions_MissingRegionAndBaseURL(t *testing.T) {
	_, err := NewOracleClient().Completions(
		context.Background(),
		&providers.Config{Credentials: providers.Credentials{ApiKey: "key"}},
		[]byte(`{}`),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "region or base_url is required")
}

func TestCompletions_RegionBuildsURLAndProjectHeader(t *testing.T) {
	const wantModel = "meta.llama-3.3-70b-instruct"
	var gotPath, gotProject string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotProject = r.Header.Get("OpenAI-Project")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"model": wantModel})
	}))
	t.Cleanup(srv.Close)

	baseURL := srv.URL + "/openai/v1"
	_, err := NewOracleClient().Completions(
		context.Background(),
		&providers.Config{
			Credentials: providers.Credentials{ApiKey: "oci-key"},
			Options: map[string]any{
				"base_url": baseURL,
				"project":  "ocid1.generativeaiproject.oc1.test",
			},
		},
		[]byte(`{"model":"`+wantModel+`","messages":[{"role":"user","content":"hi"}]}`),
	)
	require.NoError(t, err)
	assert.Equal(t, "/openai/v1/chat/completions", gotPath)
	assert.Equal(t, "ocid1.generativeaiproject.oc1.test", gotProject)
}

func TestDecodeOracleOptions_BuildsRegionalBaseURL(t *testing.T) {
	opts, err := providers.DecodeOracleOptions(map[string]any{"region": "us-chicago-1"})
	require.NoError(t, err)
	assert.Equal(
		t,
		"https://inference.generativeai.us-chicago-1.oci.oraclecloud.com/openai/v1",
		opts.BaseURL,
	)
}
