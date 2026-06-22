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

package registry

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/factory"
)

const probeTimeout = 10 * time.Second

type TestConnectionInput struct {
	GatewayID       ids.GatewayID
	RegistryID      *ids.RegistryID
	Provider        string
	ProviderOptions map[string]any
	Auth            *domain.TargetAuth
}

type TestConnectionResult struct {
	OK         bool
	Stage      string
	Provider   string
	StatusCode int
	LatencyMs  int64
	Message    string
}

//go:generate mockery --name=ConnectionTester --dir=. --output=./mocks --filename=registry_connection_tester_mock.go --case=underscore --with-expecter
type ConnectionTester interface {
	Test(ctx context.Context, in TestConnectionInput) (TestConnectionResult, error)
}

var _ ConnectionTester = (*connectionTester)(nil)

type connectionTester struct {
	finder  Finder
	locator factory.ProviderLocator
	logger  *slog.Logger
}

func NewConnectionTester(finder Finder, locator factory.ProviderLocator, logger *slog.Logger) ConnectionTester {
	return &connectionTester{
		finder:  finder,
		locator: locator,
		logger:  logger,
	}
}

func (t *connectionTester) Test(ctx context.Context, in TestConnectionInput) (TestConnectionResult, error) {
	provider, options, auth, err := t.resolveTarget(ctx, in)
	if err != nil {
		return TestConnectionResult{}, err
	}

	if unsupported, msg := unsupportedReason(auth); unsupported {
		return TestConnectionResult{
			OK:       false,
			Stage:    string(providers.StageUnsupported),
			Provider: provider,
			Message:  msg,
		}, nil
	}

	if _, err := t.locator.Get(provider); err != nil {
		return TestConnectionResult{}, fmt.Errorf("unsupported provider %q: %w", provider, commonerrors.ErrValidation)
	}

	tester, err := t.locator.GetTester(provider)
	if err != nil {
		return TestConnectionResult{
			OK:       false,
			Stage:    string(providers.StageUnsupported),
			Provider: provider,
			Message:  "connection testing is not supported for this provider yet",
		}, nil
	}

	cfg := &providers.Config{
		Options:     options,
		Credentials: auth.ProviderCredentials(),
	}

	probeCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	start := time.Now()
	result := tester.TestConnection(probeCtx, cfg)
	latency := time.Since(start)

	t.logger.Info("registry connection test",
		slog.String("provider", provider),
		slog.Bool("ok", result.OK),
		slog.String("stage", string(result.Stage)),
		slog.Int("status_code", result.StatusCode),
		slog.Int64("latency_ms", latency.Milliseconds()),
	)

	return TestConnectionResult{
		OK:         result.OK,
		Stage:      string(result.Stage),
		Provider:   provider,
		StatusCode: result.StatusCode,
		LatencyMs:  latency.Milliseconds(),
		Message:    result.Message,
	}, nil
}

func (t *connectionTester) resolveTarget(
	ctx context.Context,
	in TestConnectionInput,
) (string, map[string]any, *domain.TargetAuth, error) {
	if in.RegistryID != nil {
		reg, err := t.finder.FindByID(ctx, in.GatewayID, *in.RegistryID)
		if err != nil {
			return "", nil, nil, err
		}
		return reg.Provider(), reg.ProviderOptions(), reg.Auth(), nil
	}
	return in.Provider, in.ProviderOptions, in.Auth, nil
}

func unsupportedReason(auth *domain.TargetAuth) (bool, string) {
	if auth == nil {
		return false, ""
	}
	switch auth.Type {
	case domain.AuthTypeOAuth2:
		return true, "connection testing is not supported for oauth2 credentials yet"
	case domain.AuthTypeGCPServiceAccount:
		return true, "connection testing is not supported for gcp service account credentials yet"
	default:
		return false, ""
	}
}
