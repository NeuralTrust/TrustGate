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

package client

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"

	appmcp "github.com/NeuralTrust/TrustGate/pkg/app/mcp"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
)

const (
	codeHeaderMismatch             int64 = -32020
	codeRequiredCapability         int64 = -32021
	codeUnsupportedProtocolVersion int64 = -32022
)

// unreachableError carries the bounded failure category next to the origin it
// happened against. Both the origin it prints and the cause's text are already
// redacted by wrapUnreachable, so formatting one is always safe to log.
type unreachableError struct {
	origin   string
	category string
	cause    error
}

// Error names the bounded failure category and the origin, never the upstream's
// own text. An upstream controls that text and an upstream URL can carry a
// per-user secret in a query variable, so the cause is reachable through Unwrap
// (already redacted) but is deliberately not part of the message this error
// puts in a log or hands back to an MCP client.
func (e *unreachableError) Error() string {
	if e.origin == "" {
		return fmt.Sprintf("%s: %s", appmcp.ErrUnreachable, e.category)
	}
	return fmt.Sprintf("%s: %s: %s", appmcp.ErrUnreachable, e.category, e.origin)
}

func (e *unreachableError) Unwrap() []error {
	return []error{appmcp.ErrUnreachable, e.cause}
}

// wrapUnreachable classifies a failed connect. Both the origin it prints and the
// underlying error's text are redacted: catalog servers such as Bright Data or
// Browserbase carry the user's API token as a query variable (?token={token}),
// and this error is logged by the composer and, before the handler learned to
// map it, was returned verbatim to the MCP client.
func wrapUnreachable(origin, category string, err error) error {
	return &unreachableError{
		origin:   redactURL(origin),
		category: category,
		cause:    redactError(err, origin),
	}
}

// redactURL returns a form of the URL that is safe to log or return: userinfo
// and the fragment are dropped and every query value is replaced by the
// redaction marker. Keys are kept so the shape of the request stays
// recognisable to an operator.
func redactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		if i := strings.IndexAny(raw, "?#"); i >= 0 {
			return raw[:i]
		}
		return raw
	}
	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""
	if u.RawQuery == "" {
		return u.String()
	}
	q := u.Query()
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+secret.Redacted)
	}
	if len(parts) == 0 {
		u.RawQuery = secret.Redacted
	} else {
		u.RawQuery = strings.Join(parts, "&")
	}
	return u.String()
}

// redactError rewrites an upstream error's text so a secret carried in the
// target URL cannot leak through it. net/http's *url.Error embeds the full
// request URL — query string included — in its message, so redacting only the
// URL we print ourselves is not enough. The chain is preserved (Unwrap) so
// errors.Is on ErrUpstreamUnauthorized and friends keeps working.
func redactError(err error, rawURL string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	clean := redactText(msg, rawURL)
	if clean == msg {
		return err
	}
	return &redactedError{msg: clean, cause: err}
}

type redactedError struct {
	msg   string
	cause error
}

func (e *redactedError) Error() string { return e.msg }
func (e *redactedError) Unwrap() error { return e.cause }

// minRedactedValueLen keeps the literal-value pass from mangling error text over
// trivially short query values ("1", "true"); the URL pass still hides those
// wherever they appear inside a URL.
const minRedactedValueLen = 6

var urlInText = regexp.MustCompile(`https?://[^\s"'<>` + "`" + `]+`)

// redactText masks, in free text, (1) every literal query value and password of
// rawURL, raw and percent-escaped, longest first, and (2) the query of any URL
// embedded in the text.
func redactText(text, rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		var values []string
		for _, vs := range u.Query() {
			for _, v := range vs {
				if len(v) >= minRedactedValueLen {
					values = append(values, v, url.QueryEscape(v))
				}
			}
		}
		if u.User != nil {
			if pw, ok := u.User.Password(); ok && pw != "" {
				values = append(values, pw)
			}
		}
		sort.SliceStable(values, func(i, j int) bool { return len(values[i]) > len(values[j]) })
		for _, v := range values {
			text = strings.ReplaceAll(text, v, secret.Redacted)
		}
	}
	return urlInText.ReplaceAllStringFunc(text, redactURL)
}

func mapRPCError(err error) error {
	if err == nil {
		return nil
	}
	if je, ok := errors.AsType[*jsonrpc.Error](err); ok {
		return &appmcp.RPCError{Code: je.Code, Message: je.Message, Data: je.Data}
	}
	return err
}

func probeRPCError(err error) (*jsonrpc.Error, bool) {
	if err == nil {
		return nil, false
	}
	rpcErr, ok := errors.AsType[*jsonrpc.Error](err)
	return rpcErr, ok
}

func isModernProofRPCCode(code int64) bool {
	switch code {
	case codeHeaderMismatch, codeRequiredCapability, codeUnsupportedProtocolVersion:
		return true
	default:
		return false
	}
}

func mapItems[T any](method string, items any) ([]T, error) {
	raw, err := json.Marshal(items)
	if err != nil {
		return nil, fmt.Errorf("mcp client: %s: encode items: %w", method, err)
	}
	var out []T
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("mcp client: %s: map items: %w", method, err)
	}
	return out, nil
}
