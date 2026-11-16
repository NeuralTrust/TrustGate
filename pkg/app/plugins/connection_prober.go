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

package plugins

import (
	"context"
	"time"
)

// Probe outcome codes a ConnectionProber reports. They are a public contract:
// clients map them to their own copy.
const (
	ProbeOK                 = "ok"
	ProbeInvalidCredentials = "invalid_credentials" // #nosec G101 -- outcome code, not a credential
	ProbePermissionDenied   = "permission_denied"
	ProbeAPIDisabled        = "api_disabled"
	ProbeTemplateNotFound   = "template_not_found"
	ProbeThrottled          = "throttled"
	ProbeTimeout            = "timeout"
	ProbeUnreachable        = "unreachable"
	ProbeInvalidConfig      = "invalid_config"
)

// ConnectionProber is implemented by plugins that can check, from this
// gateway, that the service a policy's settings name is usable.
type ConnectionProber interface {
	ProbeConnection(ctx context.Context, settings map[string]any) ProbeResult
}

// ProbeResult is the outcome of one ConnectionProber call. Message never
// carries credentials or upstream response bodies.
type ProbeResult struct {
	Code    string
	Message string
	Latency time.Duration
}
