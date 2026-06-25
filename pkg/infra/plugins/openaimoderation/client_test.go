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

package openaimoderation

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func sampleModerationRequest() moderationRequest {
	return moderationRequest{
		Model: defaultModel,
		Input: []moderationInput{{Type: "text", Text: "hello world"}},
	}
}

func TestModerateDecodesResults(t *testing.T) {
	t.Parallel()
	var gotAuth, gotContentType, gotPath string
	var gotBody moderationRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotContentType = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_, _ = io.WriteString(w, `{"id":"mod-1","model":"omni-moderation-latest","results":[{"flagged":true,"categories":{"hate":true},"category_scores":{"hate":0.91}}]}`)
	}))
	defer srv.Close()

	c := newClient(2 * time.Second)
	resp, err := c.Moderate(context.Background(), srv.URL, "secret-key", sampleModerationRequest())
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "Bearer secret-key", gotAuth)
	assert.Equal(t, "application/json", gotContentType)
	assert.Equal(t, moderationsPath, gotPath)
	assert.Equal(t, defaultModel, gotBody.Model)
	require.Len(t, gotBody.Input, 1)
	assert.Equal(t, "hello world", gotBody.Input[0].Text)

	require.Len(t, resp.Results, 1)
	assert.True(t, resp.Results[0].Flagged)
	assert.InDelta(t, 0.91, resp.Results[0].CategoryScores["hate"], 1e-9)
}

func TestModerateNon2xxDoesNotLeakBody(t *testing.T) {
	t.Parallel()
	const secret = "SECRET_OPENAI_DETAIL"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"`+secret+`"}`)
	}))
	defer srv.Close()

	c := newClient(2 * time.Second)
	resp, err := c.Moderate(context.Background(), srv.URL, "k", sampleModerationRequest())
	require.Error(t, err)
	assert.Nil(t, resp)

	var modErr *errModeration
	require.True(t, errors.As(err, &modErr))
	assert.Equal(t, http.StatusInternalServerError, modErr.status)
	assert.NotContains(t, err.Error(), secret)
	assert.Contains(t, err.Error(), "500")
}

func TestModerateMalformedJSON(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{not json`)
	}))
	defer srv.Close()

	c := newClient(2 * time.Second)
	_, err := c.Moderate(context.Background(), srv.URL, "k", sampleModerationRequest())
	require.Error(t, err)
	assert.True(t, strings.Contains(err.Error(), "openai_moderation:"))
}

func TestModerateTrimsTrailingSlash(t *testing.T) {
	t.Parallel()
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = io.WriteString(w, `{"results":[]}`)
	}))
	defer srv.Close()

	c := newClient(time.Second)
	_, err := c.Moderate(context.Background(), srv.URL+"/", "k", sampleModerationRequest())
	require.NoError(t, err)
	assert.Equal(t, moderationsPath, gotPath)
}

func TestModerateContextDeadline(t *testing.T) {
	t.Parallel()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	}))
	defer srv.Close()
	defer close(release)

	c := newClient(50 * time.Millisecond)
	_, err := c.Moderate(context.Background(), srv.URL, "k", sampleModerationRequest())
	require.Error(t, err)
	assert.True(t, errors.Is(err, context.DeadlineExceeded))
}
