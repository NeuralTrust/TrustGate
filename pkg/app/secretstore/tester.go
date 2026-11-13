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

package secretstore

import (
	"context"
	"fmt"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	refdomain "github.com/NeuralTrust/TrustGate/pkg/domain/secretref"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/secretstore"
)

// Test outcomes besides an error class.
const (
	OutcomeOK      = "ok"
	OutcomeSkipped = "skipped"
)

// TestInput names what to test. With an empty Path only authentication is
// checked; Path, Version and Field are decoded, as in a parsed reference.
type TestInput struct {
	GatewayID ids.GatewayID
	Store     string
	Path      string
	Field     string
	Version   string
}

// TestResult is the outcome of a test. It never holds the secret value.
type TestResult struct {
	// Auth is "ok" or the error class of authenticating to the store.
	Auth string
	// Read is "ok", "skipped" (no path, or authentication failed) or the
	// error class of reading the path and selecting the field.
	Read string
	// Version is the version the store reported for the read, if any.
	Version string
	Latency time.Duration
}

//go:generate mockery --name=Tester --dir=. --output=./mocks --filename=secretstore_tester_mock.go --case=underscore --with-expecter

// Tester checks, live and bypassing the cache, that this plane can
// authenticate to a store and read a path from it.
type Tester interface {
	Test(ctx context.Context, in TestInput) (TestResult, error)
}

// TesterConfig configures NewTester.
type TesterConfig struct {
	// Catalog is the plane's loaded stores; nil when it loads none.
	Catalog     domain.Catalog
	Eligibility domain.Eligibility
	// Gateways reads the gateway for the eligibility check; nil skips it.
	Gateways GatewayReader
	// Timeout bounds each call to the store.
	Timeout time.Duration
}

type tester struct {
	cfg TesterConfig
}

// NewTester returns a Tester over the plane's own catalog.
func NewTester(cfg TesterConfig) Tester {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 2 * time.Second
	}
	return &tester{cfg: cfg}
}

// Test refuses, as errors, what a reference could never do on this plane: a
// plane without stores or an ineligible gateway, a store that is missing or
// whose allowlist excludes the gateway, a malformed or disallowed path, a
// version on a store without versions. Everything the store itself answers
// is a result.
func (t *tester) Test(ctx context.Context, in TestInput) (TestResult, error) {
	if t.cfg.Catalog == nil {
		return TestResult{}, refdomain.ErrReferencesNotSupported
	}
	if err := t.checkEligible(ctx, in.GatewayID); err != nil {
		return TestResult{}, err
	}
	store, backend, ok := t.cfg.Catalog.Get(in.Store)
	if !ok || !store.AdmitsGateway(in.GatewayID) {
		return TestResult{}, fmt.Errorf("%w: %q", refdomain.ErrUnknownStore, in.Store)
	}
	if in.Path != "" {
		if err := checkTestPath(store, in); err != nil {
			return TestResult{}, err
		}
	} else if in.Field != "" || in.Version != "" {
		return TestResult{}, fmt.Errorf("%w: a field or version needs a path", refdomain.ErrInvalidReference)
	}

	started := time.Now()
	res := TestResult{Auth: OutcomeOK, Read: OutcomeSkipped}
	probeCtx, cancel := context.WithTimeout(ctx, t.cfg.Timeout)
	err := backend.Probe(probeCtx)
	cancel()
	if err != nil {
		res.Auth = string(domain.ClassOf(err))
		res.Latency = time.Since(started)
		return res, nil
	}
	if in.Path != "" {
		res.Read, res.Version = t.read(ctx, backend, in)
	}
	res.Latency = time.Since(started)
	return res, nil
}

func (t *tester) read(ctx context.Context, backend domain.Backend, in TestInput) (outcome, version string) {
	fetchCtx, cancel := context.WithTimeout(ctx, t.cfg.Timeout)
	defer cancel()
	secret, err := backend.Fetch(fetchCtx, in.Path, in.Version)
	if err != nil {
		return string(domain.ClassOf(err)), ""
	}
	if _, err := secret.Select(in.Field); err != nil {
		return string(domain.ClassOf(err)), secret.Version()
	}
	return OutcomeOK, secret.Version()
}

func (t *tester) checkEligible(ctx context.Context, gwID ids.GatewayID) error {
	if t.cfg.Eligibility == domain.EligibilityAll || t.cfg.Gateways == nil {
		return nil
	}
	gw, err := t.cfg.Gateways.FindByID(ctx, gwID)
	if err != nil {
		return err
	}
	if !domain.Eligible(t.cfg.Eligibility, gw) {
		return refdomain.ErrReferencesNotSupported
	}
	return nil
}

// checkTestPath applies the reference grammar and the store's rules to the
// decoded path, field and version, as if they had been written as a
// reference.
func checkTestPath(store *domain.Store, in TestInput) error {
	ref := refdomain.Ref{Store: store.Name, Path: in.Path, Version: in.Version, Field: in.Field}
	parsed, _, err := refdomain.Parse(ref.String())
	if err != nil {
		return err
	}
	if parsed.Path != in.Path || parsed.Field != in.Field || parsed.Version != in.Version {
		return fmt.Errorf("%w: the path, field or version does not round-trip", refdomain.ErrInvalidReference)
	}
	if !store.AllowsPath(in.Path) {
		return fmt.Errorf("%w: %s", refdomain.ErrPathNotAllowed, in.Path)
	}
	if in.Version != "" && (store.Type == domain.TypeFile || store.Type == domain.TypeEnv) {
		return fmt.Errorf("%w: %s stores have no versions", refdomain.ErrInvalidReference, store.Type)
	}
	return nil
}
