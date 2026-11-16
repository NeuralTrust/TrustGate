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

package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/common/secret"
	gatewaydomain "github.com/NeuralTrust/TrustGate/pkg/domain/gateway"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
)

// ErrConnectionTestUnsupported is a connection test for a plugin that cannot
// probe its upstream.
var ErrConnectionTestUnsupported = fmt.Errorf("policy: plugin does not support connection tests: %w", commonerrors.ErrValidation)

// Outcome codes the tester reports itself, next to the plugin's probe codes.
const (
	CodeReenterCredentials = "reenter_credentials" // #nosec G101 -- outcome code, not a credential
	CodeNotSynced          = "not_synced"
)

// TestConnectionInput is a connection test of Settings for the plugin Slug.
// PolicyID names the stored policy whose credentials stand in for masked
// values. OnDataPlane is set when the test runs on a data plane, whose policy
// snapshot can lag a save.
type TestConnectionInput struct {
	GatewayID   ids.GatewayID
	PolicyID    *ids.PolicyID
	Slug        string
	Settings    map[string]any
	OnDataPlane bool
}

// TestConnectionResult is the outcome of a connection test. Message never
// carries credentials.
type TestConnectionResult struct {
	OK      bool
	Code    string
	Message string
	Latency time.Duration
}

//go:generate mockery --name=ConnectionTester --dir=. --output=./mocks --filename=policy_connection_tester_mock.go --case=underscore --with-expecter
type ConnectionTester interface {
	Test(ctx context.Context, in TestConnectionInput) (TestConnectionResult, error)
}

var _ ConnectionTester = (*connectionTester)(nil)

type connectionTester struct {
	repo     domain.Repository
	gateways gatewaydomain.Repository
	registry appplugins.Registry
	logger   *slog.Logger
}

func NewConnectionTester(
	repo domain.Repository,
	gateways gatewaydomain.Repository,
	registry appplugins.Registry,
	logger *slog.Logger,
) ConnectionTester {
	return &connectionTester{repo: repo, gateways: gateways, registry: registry, logger: logger}
}

func (t *connectionTester) Test(ctx context.Context, in TestConnectionInput) (TestConnectionResult, error) {
	if !in.OnDataPlane {
		gw, err := t.gateways.FindByID(ctx, in.GatewayID)
		if err != nil {
			return TestConnectionResult{}, err
		}
		if gw.ServedByHybridDataPlane() {
			return TestConnectionResult{}, domain.ErrTestRunsOnDataPlane
		}
	}
	plugin, ok := t.registry.Get(in.Slug)
	if !ok {
		return TestConnectionResult{}, fmt.Errorf("unknown plugin %q: %w", in.Slug, domain.ErrInvalidSlug)
	}
	prober, ok := plugin.(appplugins.ConnectionProber)
	if !ok {
		return TestConnectionResult{}, ErrConnectionTestUnsupported
	}

	candidate := appplugins.StripRetiredSettings(t.registry, in.Slug, cloneSettings(in.Settings))
	if candidate == nil {
		candidate = map[string]any{}
	}
	paths, _ := appplugins.PluginCredentialPaths(t.registry, in.Slug)
	dests := appplugins.PluginCredentialDestinations(t.registry, in.Slug)
	if err := secret.RejectCaseVariants(candidate, dests); err != nil {
		return TestConnectionResult{}, errors.Join(commonerrors.ErrValidation, err)
	}

	var previous map[string]any
	if in.PolicyID != nil {
		stored, err := t.storedPolicy(ctx, in)
		if errors.Is(err, commonerrors.ErrNotFound) && in.OnDataPlane {
			return t.report(in, notSynced()), nil
		}
		if err != nil {
			return TestConnectionResult{}, err
		}
		if err := secret.ResolveSettings(candidate, stored.Settings, paths, dests); err != nil {
			if errors.Is(err, secret.ErrReenterCredentials) {
				return t.report(in, TestConnectionResult{
					Code:    CodeReenterCredentials,
					Message: "Enter the credential again: the stored one cannot be reused after changing where it is sent.",
				}), nil
			}
			return TestConnectionResult{}, errors.Join(commonerrors.ErrValidation, err)
		}
		if in.OnDataPlane && hasMaskedCredential(candidate, paths) {
			return t.report(in, notSynced()), nil
		}
		previous = stored.Settings
	}

	if err := secret.ValidateCredentialSettings(candidate, paths); err != nil {
		return TestConnectionResult{}, errors.Join(commonerrors.ErrValidation, err)
	}
	if err := t.registry.Validate(in.Slug, candidate); err != nil {
		return TestConnectionResult{}, errors.Join(commonerrors.ErrValidation, err)
	}
	if err := t.registry.ValidateSettingsWrite(in.Slug, candidate, previous); err != nil {
		return TestConnectionResult{}, errors.Join(commonerrors.ErrValidation, err)
	}

	probe := prober.ProbeConnection(ctx, candidate)
	return t.report(in, TestConnectionResult{
		OK:      probe.Code == appplugins.ProbeOK,
		Code:    probe.Code,
		Message: probe.Message,
		Latency: probe.Latency,
	}), nil
}

func (t *connectionTester) storedPolicy(ctx context.Context, in TestConnectionInput) (*domain.Policy, error) {
	stored, err := t.repo.FindByID(ctx, *in.PolicyID)
	if err != nil {
		return nil, err
	}
	if stored.GatewayID != in.GatewayID || stored.Slug != in.Slug {
		return nil, domain.ErrNotFound
	}
	return stored, nil
}

func hasMaskedCredential(settings map[string]any, paths []string) bool {
	for _, path := range paths {
		if v, ok := secret.SettingString(settings, path); ok && secret.IsMasked(v) {
			return true
		}
	}
	return false
}

func notSynced() TestConnectionResult {
	return TestConnectionResult{
		Code:    CodeNotSynced,
		Message: "This policy has not reached the gateway's data plane yet. Try again in a few seconds.",
	}
}

func (t *connectionTester) report(in TestConnectionInput, res TestConnectionResult) TestConnectionResult {
	if t.logger != nil {
		attrs := []any{
			slog.String("gateway_id", in.GatewayID.String()),
			slog.String("slug", in.Slug),
			slog.Bool("ok", res.OK),
			slog.String("code", res.Code),
			slog.Int64("latency_ms", res.Latency.Milliseconds()),
			slog.Bool("data_plane", in.OnDataPlane),
		}
		if in.PolicyID != nil {
			attrs = append(attrs, slog.String("policy_id", in.PolicyID.String()))
		}
		t.logger.Info("policy connection test", attrs...)
	}
	return res
}
