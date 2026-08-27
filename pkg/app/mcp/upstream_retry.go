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

	appconsumer "github.com/NeuralTrust/TrustGate/pkg/app/consumer"
	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type credentialRefresher interface {
	Refresh(context.Context, *appconsumer.RoutableConsumer, *registrydomain.Registry, *Target) error
}

// invokeUpstream refreshes a rejected forwarded credential and retries once.
// The retry is bounded so revoked grants cannot create an authentication loop.
func invokeUpstream[T any](
	c *composer,
	ctx context.Context,
	rc *appconsumer.RoutableConsumer,
	reg *registrydomain.Registry,
	invoke func(Upstream) (T, error),
) (T, error) {
	target, err := c.target(ctx, rc, reg)
	if err != nil {
		var zero T
		return zero, err
	}
	out, err := invokeTarget(c, ctx, target, invoke)
	if !errors.Is(err, ErrUpstreamUnauthorized) || c.creds == nil {
		return out, err
	}
	refresher, ok := c.creds.(credentialRefresher)
	if !ok {
		return out, err
	}
	if refreshErr := refresher.Refresh(ctx, rc, reg, &target); refreshErr != nil {
		if errors.Is(refreshErr, errCredentialRefreshUnsupported) ||
			errors.Is(refreshErr, errCredentialRefreshThrottled) {
			return out, err
		}
		var zero T
		return zero, refreshErr
	}
	return invokeTarget(c, ctx, target, invoke)
}

func invokeTarget[T any](
	c *composer,
	ctx context.Context,
	target Target,
	invoke func(Upstream) (T, error),
) (T, error) {
	up, err := c.dialer.Connect(ctx, target)
	if err != nil {
		var zero T
		return zero, err
	}
	defer up.Close(ctx)
	return invoke(up)
}
