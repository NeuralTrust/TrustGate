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

package database

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/config"
	"github.com/jackc/pgx/v5"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

const (
	gcpTokenRefreshMargin = 5 * time.Minute
	gcpTokenFetchTimeout  = 20 * time.Second
)

// One token carries both scopes, so the same identity logs in to Cloud SQL and
// AlloyDB alike.
var gcpDatabaseScopes = []string{
	"https://www.googleapis.com/auth/sqlservice.login",
	"https://www.googleapis.com/auth/alloydb.login",
}

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

func newGCPAuthStrategy(_ context.Context, _ *config.DatabaseConfig, dependencies authDependencies) (poolAuthStrategy, error) {
	source, err := dependencies.loadGCPTokenSource(gcpDatabaseScopes...)
	if err != nil {
		return nil, fmt.Errorf("load google cloud database authentication credential: %w", err)
	}
	// The reuse source holds its lock across a refresh, so a burst of new pooled
	// connections collapses into a single token request.
	tokens := oauth2.ReuseTokenSourceWithExpiry(nil, source, gcpTokenRefreshMargin)
	return newTokenAuthStrategy(func(context.Context, *pgx.ConnConfig) (string, error) {
		return gcpToken(tokens, gcpTokenFetchTimeout)
	}), nil
}

// gcpToken bounds a fetch that oauth2 offers no context for. It deliberately
// ignores the connection's deadline, as the Azure cache does: callers queue on
// the reuse source's lock, and a deadline that started before the wait would be
// spent by the time they reach the fetch.
func gcpToken(tokens oauth2.TokenSource, timeout time.Duration) (string, error) {
	type result struct {
		token *oauth2.Token
		err   error
	}
	results := make(chan result, 1)
	go func() {
		token, err := tokens.Token()
		results <- result{token, err}
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case fetched := <-results:
		if fetched.err != nil {
			return "", fetched.err
		}
		if fetched.token.AccessToken == "" {
			return "", errGCPTokenEmpty
		}
		return fetched.token.AccessToken, nil
	case <-timer.C:
		return "", errGCPTokenTimeout
	}
}
