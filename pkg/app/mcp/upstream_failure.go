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
	"net"
	"net/http"
)

// Why a dial or a discovery failed, as the inventory is allowed to say it.
// The phrases are the whole of the text a caller sees: hosts, redirect
// targets and upstream bodies stay in the log.
const (
	UpstreamFailureCredential = "credential"
	UpstreamFailureRedirect   = "redirect"
	UpstreamFailureDowngrade  = "downgrade"
	UpstreamFailureDNS        = "dns"
	UpstreamFailureTimeout    = "timeout"
)

// errDiscoveryTimedOut marks a discovery whose own deadline fired. It is not a
// context.DeadlineExceeded, so the negative cache can keep it: that cache
// drops cancellation and deadlines, which would otherwise forget the timeout
// and dial the same server again on the next request.
var errDiscoveryTimedOut = errors.New("discovery timed out")

// UpstreamFailure is a dial or discovery failure whose cause the inventory
// can name. Error is the phrase only. Unwrap yields ErrUpstreamUnauthorized
// for an HTTP 401, and nothing for a 403: a 403 is a rejected credential, but
// it is not the signal the refresh retry keys on.
type UpstreamFailure struct {
	Kind   string
	Status int
}

func (f *UpstreamFailure) Error() string {
	if f == nil {
		return ""
	}
	return f.StatusPhrase()
}

func (f *UpstreamFailure) Unwrap() error {
	if f != nil && f.Kind == UpstreamFailureCredential && f.Status == http.StatusUnauthorized {
		return ErrUpstreamUnauthorized
	}
	return nil
}

// StatusPhrase is the cause as a caller may read it. It never includes a host,
// a redirect target, or an upstream body.
func (f *UpstreamFailure) StatusPhrase() string {
	if f == nil {
		return "the gateway could not reach it"
	}
	switch f.Kind {
	case UpstreamFailureCredential:
		return fmt.Sprintf("the server rejected the credential (HTTP %d)", f.Status)
	case UpstreamFailureRedirect:
		return fmt.Sprintf("upstream redirected (HTTP %d) — not followed", f.Status)
	case UpstreamFailureDowngrade:
		return "redirect to http:// refused"
	case UpstreamFailureDNS:
		return "DNS or connect failure"
	case UpstreamFailureTimeout:
		return "the request timed out"
	default:
		return "the gateway could not reach it"
	}
}

// ClassifyUpstreamFailure names a dial or discovery failure when the chain
// says why. Nil when the failure is not one of those causes.
func ClassifyUpstreamFailure(err error) *UpstreamFailure {
	if err == nil {
		return nil
	}
	var typed *UpstreamFailure
	if errors.As(err, &typed) && typed != nil {
		return typed
	}
	if errors.Is(err, errDiscoveryTimedOut) || errors.Is(err, context.DeadlineExceeded) {
		return &UpstreamFailure{Kind: UpstreamFailureTimeout}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &UpstreamFailure{Kind: UpstreamFailureTimeout}
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return &UpstreamFailure{Kind: UpstreamFailureDNS}
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && (opErr.Op == "dial" || opErr.Op == "connect") {
		return &UpstreamFailure{Kind: UpstreamFailureDNS}
	}
	if errors.Is(err, ErrUpstreamUnauthorized) {
		return &UpstreamFailure{Kind: UpstreamFailureCredential, Status: http.StatusUnauthorized}
	}
	return nil
}

// inventoryCauseForFailure is the inventory cause code for a classified dial
// failure. Empty when the failure is not one the status text can name.
func inventoryCauseForFailure(err error) string {
	f := ClassifyUpstreamFailure(err)
	if f == nil {
		return ""
	}
	switch f.Kind {
	case UpstreamFailureCredential:
		status := f.Status
		if status == 0 {
			status = http.StatusUnauthorized
		}
		return fmt.Sprintf("credential_rejected_%d", status)
	case UpstreamFailureRedirect:
		return fmt.Sprintf("redirect_not_followed_%d", f.Status)
	case UpstreamFailureDowngrade:
		return "redirect_http_refused"
	case UpstreamFailureDNS:
		return "dns"
	case UpstreamFailureTimeout:
		return "timeout"
	default:
		return ""
	}
}
