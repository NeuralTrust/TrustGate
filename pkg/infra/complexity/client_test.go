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

package complexity

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClient_Configured(t *testing.T) {
	t.Parallel()
	assert.False(t, NewClient("", "", 0).Configured())
	assert.False(t, NewClient("http://x", "", 0).Configured())
	assert.False(t, NewClient("", "tok", 0).Configured())
	assert.True(t, NewClient("http://x", "tok", 0).Configured())
}

func TestClient_Score_Success(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, complexityPath, r.URL.Path)
		assert.Equal(t, "secret-token", r.Header.Get(headerToken))
		body, _ := io.ReadAll(r.Body)
		var got scoreRequest
		require.NoError(t, json.Unmarshal(body, &got))
		assert.Equal(t, "hello", got.Input)
		assert.Equal(t, "chat_1", got.ConversationID)
		assert.Equal(t, "tenant_1", got.TenantID)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(scoreResponse{Score: 0.41, RawScore: 0.38})
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "secret-token", time.Second)
	score, err := c.Score(context.Background(), "hello", "chat_1", "tenant_1")
	require.NoError(t, err)
	assert.InDelta(t, 0.41, score, 1e-9)
}

func TestClient_Score_NotConfigured(t *testing.T) {
	t.Parallel()
	c := NewClient("", "", time.Second)
	_, err := c.Score(context.Background(), "hello", "", "")
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestClient_Score_Unauthorized(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "bad", time.Second)
	_, err := c.Score(context.Background(), "hello", "", "")
	assert.ErrorIs(t, err, ErrUnauthorized)
}

func TestClient_Score_ServerError(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewClient(srv.URL, "tok", time.Second)
	_, err := c.Score(context.Background(), "hello", "", "")
	require.Error(t, err)
	assert.False(t, errors.Is(err, ErrUnauthorized))
}
