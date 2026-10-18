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

package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestClassifyUpstreamFailure_Phrases(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		err    error
		kind   string
		status int
		phrase string
		unauth bool
		cause  string
	}{
		{
			name:   "401",
			err:    &UpstreamFailure{Kind: UpstreamFailureCredential, Status: http.StatusUnauthorized},
			kind:   UpstreamFailureCredential,
			status: http.StatusUnauthorized,
			phrase: "the server rejected the credential (HTTP 401)",
			unauth: true,
			cause:  "credential_rejected_401",
		},
		{
			name:   "403 is not the refresh signal",
			err:    &UpstreamFailure{Kind: UpstreamFailureCredential, Status: http.StatusForbidden},
			kind:   UpstreamFailureCredential,
			status: http.StatusForbidden,
			phrase: "the server rejected the credential (HTTP 403)",
			cause:  "credential_rejected_403",
		},
		{
			name:   "308",
			err:    fmt.Errorf("dial: %w", &UpstreamFailure{Kind: UpstreamFailureRedirect, Status: http.StatusPermanentRedirect}),
			kind:   UpstreamFailureRedirect,
			status: http.StatusPermanentRedirect,
			phrase: "upstream redirected (HTTP 308) — not followed",
			cause:  "redirect_not_followed_308",
		},
		{
			name:   "307 downgrade",
			err:    &UpstreamFailure{Kind: UpstreamFailureDowngrade, Status: http.StatusTemporaryRedirect},
			kind:   UpstreamFailureDowngrade,
			status: http.StatusTemporaryRedirect,
			phrase: "redirect to http:// refused",
			cause:  "redirect_http_refused",
		},
		{
			name:   "dns",
			err:    fmt.Errorf("%w: %w", ErrUnreachable, &net.DNSError{Err: "no such host", Name: "mcp.example", IsNotFound: true}),
			kind:   UpstreamFailureDNS,
			phrase: "DNS or connect failure",
			cause:  "dns",
		},
		{
			name:   "connect",
			err:    &net.OpError{Op: "dial", Err: errors.New("connect: connection refused")},
			kind:   UpstreamFailureDNS,
			phrase: "DNS or connect failure",
			cause:  "dns",
		},
		{
			name:   "deadline",
			err:    fmt.Errorf("discover: %w", context.DeadlineExceeded),
			kind:   UpstreamFailureTimeout,
			phrase: "the request timed out",
			cause:  "timeout",
		},
		{
			name:   "discovery timeout sentinel",
			err:    fmt.Errorf("%w: %w", ErrUnreachable, errDiscoveryTimedOut),
			kind:   UpstreamFailureTimeout,
			phrase: "the request timed out",
			cause:  "timeout",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyUpstreamFailure(tc.err)
			if got == nil || got.Kind != tc.kind || got.Status != tc.status {
				t.Fatalf("classified = %+v, want kind %s status %d", got, tc.kind, tc.status)
			}
			if got.StatusPhrase() != tc.phrase {
				t.Fatalf("phrase = %q, want %q", got.StatusPhrase(), tc.phrase)
			}
			if strings.Contains(got.StatusPhrase(), "mcp.example") || strings.Contains(got.StatusPhrase(), "10.") {
				t.Fatalf("phrase names a host: %q", got.StatusPhrase())
			}
			if errors.Is(tc.err, ErrUpstreamUnauthorized) != tc.unauth {
				t.Fatalf("errors.Is ErrUpstreamUnauthorized = %v, want %v", errors.Is(tc.err, ErrUpstreamUnauthorized), tc.unauth)
			}
			if cause := inventoryCauseForFailure(tc.err); cause != tc.cause {
				t.Fatalf("cause = %q, want %q", cause, tc.cause)
			}
		})
	}
}

func TestRefreshDiscovery_TimeoutIsClassified(t *testing.T) {
	cache := newMapCache()
	c := &composer{discovery: cache, logger: slog.New(slog.DiscardHandler)}
	ctx, cancel := context.WithTimeout(context.Background(), time.Nanosecond)
	defer cancel()
	time.Sleep(time.Millisecond)
	stored := discoveryFailureError(ctx, ctx.Err())
	if ClassifyUpstreamFailure(stored) == nil || ClassifyUpstreamFailure(stored).StatusPhrase() != "the request timed out" {
		t.Fatalf("stored discovery timeout = %v", stored)
	}
	rememberFailure[[]Tool](c, "tools:k", stored)
	cached, ok := cache.Get("tools:k")
	if !ok {
		t.Fatal("the timeout must be remembered")
	}
	fail, ok := cached.(discoveryFailure)
	if !ok {
		t.Fatalf("cached = %T", cached)
	}
	if got := ClassifyUpstreamFailure(fail.err); got == nil || got.Kind != UpstreamFailureTimeout {
		t.Fatalf("cached failure classified as %+v", got)
	}
}
