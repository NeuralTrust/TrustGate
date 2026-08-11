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
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpguts"
)

const responseHeaderTimeout = 30 * time.Second

var (
	errRedirectRejected = errors.New("mcp upstream redirect rejected")
	sharedHTTPTransport = func() http.RoundTripper {
		transport, ok := http.DefaultTransport.(*http.Transport)
		if !ok {
			return http.DefaultTransport
		}
		cloned := transport.Clone()
		cloned.ResponseHeaderTimeout = responseHeaderTimeout
		return cloned
	}()
)

var reservedTargetHeaders = map[string]struct{}{
	"accept":               {},
	"connection":           {},
	"content-length":       {},
	"content-type":         {},
	"host":                 {},
	"last-event-id":        {},
	"mcp-method":           {},
	"mcp-name":             {},
	"mcp-protocol-version": {},
	"mcp-session-id":       {},
	"trailer":              {},
	"transfer-encoding":    {},
	"user-agent":           {},
}

func canonicalOrigin(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", errors.New("upstream URL syntax is invalid")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("upstream URL scheme is unsupported")
	}
	if parsed.User != nil {
		return "", errors.New("upstream URL userinfo is not allowed")
	}
	if strings.Contains(rawURL, "#") {
		return "", errors.New("upstream URL fragment is not allowed")
	}
	if parsed.Opaque != "" || parsed.Host == "" {
		return "", errors.New("upstream URL must be absolute with a host")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("upstream URL contains an empty explicit port")
	}

	hostname := strings.ToLower(parsed.Hostname())
	if hostname == "" {
		return "", errors.New("upstream URL host is empty")
	}
	if strings.Contains(hostname, ":") {
		ip := net.ParseIP(hostname)
		if ip == nil || ip.To4() != nil {
			return "", errors.New("upstream URL contains invalid IPv6 host")
		}
		hostname = strings.ToLower(ip.String())
	}

	port := parsed.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil || portNumber == 0 {
		return "", errors.New("upstream URL port is invalid")
	}
	port = strconv.FormatUint(portNumber, 10)

	return scheme + "://" + net.JoinHostPort(hostname, port), nil
}

func newTargetHTTPClient(headers map[string]string) (*http.Client, error) {
	return newTargetHTTPClientWithTransport(headers, sharedHTTPTransport)
}

func newTargetHTTPClientWithTransport(headers map[string]string, transport http.RoundTripper) (*http.Client, error) {
	if transport == nil {
		return nil, errors.New("upstream HTTP transport is nil")
	}
	targetHeaders := make(http.Header, len(headers))
	keys := make([]string, 0, len(headers))
	for key := range headers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	seen := make(map[string]struct{}, len(headers))
	for _, key := range keys {
		value := headers[key]
		normalized := strings.ToLower(strings.TrimSpace(key))
		if !httpguts.ValidHeaderFieldName(key) || !httpguts.ValidHeaderFieldValue(value) {
			return nil, fmt.Errorf("invalid upstream header %q", key)
		}
		if _, duplicate := seen[normalized]; duplicate {
			return nil, fmt.Errorf("duplicate upstream header %q", normalized)
		}
		seen[normalized] = struct{}{}
		if _, reserved := reservedTargetHeaders[normalized]; reserved || strings.HasPrefix(normalized, "mcp-param-") {
			return nil, fmt.Errorf("reserved upstream header %q", key)
		}
		targetHeaders.Set(key, value)
	}
	return &http.Client{
		Transport: &targetHeaderRoundTripper{
			transport: transport,
			headers:   targetHeaders,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errRedirectRejected
		},
	}, nil
}

type targetHeaderRoundTripper struct {
	transport http.RoundTripper
	headers   http.Header
}

func (t *targetHeaderRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	cloned := req.Clone(req.Context())
	cloned.Header = req.Header.Clone()
	for key, values := range t.headers {
		cloned.Header.Del(key)
		for _, value := range values {
			cloned.Header.Add(key, value)
		}
	}
	return t.transport.RoundTrip(cloned)
}
