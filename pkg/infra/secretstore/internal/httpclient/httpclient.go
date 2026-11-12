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

// Package httpclient builds the HTTP clients secret store backends talk to
// their store with, and classifies what they get back.
package httpclient

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// MaxBodyBytes bounds a store response read into memory.
const MaxBodyBytes = 1 << 20

// New returns a client that trusts caFile when set, and the system roots
// otherwise. It honours the environment's proxy settings, which customer
// networks often require. Requests are bounded by their context.
func New(caFile string) (*http.Client, error) {
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pem, err := os.ReadFile(caFile) // #nosec G304 -- operator-configured CA file from the store file
		if err != nil {
			return nil, fmt.Errorf("%w: reading the CA file: %v", secretstore.ErrInvalidStore, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%w: the CA file holds no PEM certificate", secretstore.ErrInvalidStore)
		}
		tlsConfig.RootCAs = pool
	}
	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		TLSClientConfig:       tlsConfig,
		TLSHandshakeTimeout:   5 * time.Second,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, nil
}

// ReadBody reads a response body up to MaxBodyBytes and closes it.
func ReadBody(resp *http.Response) ([]byte, error) {
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading the response failed", secretstore.ErrUnavailable)
	}
	if len(raw) > MaxBodyBytes {
		return nil, fmt.Errorf("%w: the response is larger than %d bytes", secretstore.ErrInvalidPayload, MaxBodyBytes)
	}
	return raw, nil
}

// Discard drains and closes a body whose content is not needed.
func Discard(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, MaxBodyBytes)) // best effort, to reuse the connection
	_ = resp.Body.Close()                                               // nothing to do about a failed close
}

// TransportError classifies a request that got no response. Only the class
// and a generic message are kept: the underlying error can name the URL.
func TransportError(err error) error {
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return fmt.Errorf("%w: the store did not answer in time", secretstore.ErrUnavailable)
	}
	return fmt.Errorf("%w: the store could not be reached", secretstore.ErrUnavailable)
}

// StatusError classifies an HTTP status of a secret read. Only a status that
// says the secret does not exist or may not be read withdraws a value; any
// other unexpected answer, such as a redirect from a standby node, counts as
// the store being unavailable, so the last good value keeps being served.
// Bodies are never included: they can echo request data.
func StatusError(status int) error {
	switch status {
	case http.StatusNotFound, http.StatusBadRequest:
		return fmt.Errorf("%w: the store answered %d", secretstore.ErrNotFound, status)
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: the store answered %d", secretstore.ErrAuthFailed, status)
	case http.StatusForbidden:
		return fmt.Errorf("%w: the store answered %d", secretstore.ErrAccessDenied, status)
	default:
		return fmt.Errorf("%w: the store answered %d", secretstore.ErrUnavailable, status)
	}
}
