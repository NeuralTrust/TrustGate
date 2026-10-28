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

package cache

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	redisLoginGCP         = "gcp"
	gcpTokenRefreshMargin = 5 * time.Minute
	gcpTokenFetchTimeout  = 20 * time.Second
)

// Memorystore authorizes the identity through its IAM role
// (roles/redis.dbConnectionUser), not through a service-specific scope, so the
// token carries the cloud-platform scope its documentation names.
var gcpRedisScopes = []string{"https://www.googleapis.com/auth/cloud-platform"}

var (
	errGCPTokenTimeout = errors.New("google cloud token request timed out")
	errGCPTokenEmpty   = errors.New("google cloud returned an empty access token")
)

type gcpTokenSourceLoader func(scopes ...string) (oauth2.TokenSource, error)

func defaultGCPTokenSource(scopes ...string) (oauth2.TokenSource, error) {
	// The token source keeps this context for every later refresh, so it must not
	// be a boot or connection context that is cancelled once that call returns.
	// The client timeout ends a stuck STS or OAuth exchange instead of leaving it
	// holding the token cache.
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, &http.Client{Timeout: gcpTokenFetchTimeout})
	credentials, err := google.FindDefaultCredentials(ctx, scopes...)
	if err != nil {
		return nil, fmt.Errorf("find google application default credentials: %w", err)
	}
	return credentials.TokenSource, nil
}

// newGCPCredentialsProvider authenticates each new connection with a Google
// access token as the AUTH password and no username. Memorystore keeps an
// authenticated connection valid after its token expires, so the token is only
// needed when a connection is opened.
func newGCPCredentialsProvider(deps redisAuthDependencies) (credentialsProvider, error) {
	source, err := deps.loadGCPTokenSource(gcpRedisScopes...)
	if err != nil {
		return nil, fmt.Errorf("load google cloud redis authentication credential: %w", err)
	}
	fetcher := &gcpTokenFetcher{
		tokens:  oauth2.ReuseTokenSourceWithExpiry(nil, source, gcpTokenRefreshMargin),
		timeout: gcpTokenFetchTimeout,
	}
	return func(context.Context) (string, string, error) {
		token, err := fetcher.token()
		if err != nil {
			return "", "", fmt.Errorf("fetch google cloud redis access token: %w", err)
		}
		return "", token, nil
	}, nil
}

// gcpTokenFetcher bounds a fetch that oauth2 offers no context for, and runs
// at most one fetch at a time: callers that arrive while a fetch is running
// wait for it instead of starting their own. A caller that times out leaves
// the fetch running, so a stalled token endpoint holds one goroutine, not one
// per new connection.
type gcpTokenFetcher struct {
	tokens  oauth2.TokenSource
	timeout time.Duration

	mutex   sync.Mutex
	pending *gcpTokenFetch
}

type gcpTokenFetch struct {
	done  chan struct{}
	token string
	err   error
}

// token deliberately ignores the connection's deadline: a caller may join a
// fetch that is already running, and a deadline that started before the
// connection was dialed could be spent before the fetch can finish.
func (f *gcpTokenFetcher) token() (string, error) {
	f.mutex.Lock()
	fetch := f.pending
	if fetch == nil {
		fetch = &gcpTokenFetch{done: make(chan struct{})}
		f.pending = fetch
		go f.run(fetch)
	}
	f.mutex.Unlock()

	timer := time.NewTimer(f.timeout)
	defer timer.Stop()
	select {
	case <-fetch.done:
		return fetch.token, fetch.err
	case <-timer.C:
		return "", errGCPTokenTimeout
	}
}

func (f *gcpTokenFetcher) run(fetch *gcpTokenFetch) {
	token, err := f.tokens.Token()
	switch {
	case err != nil:
		fetch.err = err
	case token.AccessToken == "":
		fetch.err = errGCPTokenEmpty
	default:
		fetch.token = token.AccessToken
	}
	f.mutex.Lock()
	f.pending = nil
	f.mutex.Unlock()
	close(fetch.done)
}
