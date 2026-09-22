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
	"fmt"

	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	consumerdomain "github.com/NeuralTrust/TrustGate/pkg/domain/consumer"
)

var (
	ErrToolNotFound        = fmt.Errorf("mcp: tool not found: %w", commonerrors.ErrNotFound)
	ErrPromptNotFound      = fmt.Errorf("mcp: prompt not found: %w", commonerrors.ErrNotFound)
	ErrResourceNotFound    = fmt.Errorf("mcp: resource not found: %w", commonerrors.ErrNotFound)
	ErrNoMCPRegistries     = fmt.Errorf("mcp: no MCP registries attached to consumer: %w", commonerrors.ErrValidation)
	ErrUpstreamUnavailable = fmt.Errorf("mcp: upstream unavailable")
)

// ErrRegistryNotIntrospectable reports a registry whose upstream cannot be
// dialed from the admin plane because the dial depends on a principal the admin
// request does not carry: per-principal auth supplies the credential, URL
// variables supply the host. It wraps commonerrors.ErrConflict so the HTTP
// funnel answers 409.
var ErrRegistryNotIntrospectable = fmt.Errorf(
	"mcp: registry cannot be introspected without a principal: %w",
	commonerrors.ErrConflict,
)

// ToolNotPermittedError reports a tool the upstream offers but the consumer's
// toolkit excludes. It is a denial, not a missing tool and not an upstream
// failure, so it carries its own type: the handler answers it as a policy block
// the agent can read, while telemetry records it as forbidden.
type ToolNotPermittedError struct {
	Tool string
}

func (e *ToolNotPermittedError) Error() string {
	return fmt.Sprintf("mcp: tool %q is not permitted for this consumer", e.Tool)
}

// ApplicationNotConnectedError reports a server the calling application has no
// account on. It is the machine's counterpart to ConsentRequiredError: a
// consumer that acts as itself has no person behind the request, so there is
// nobody to walk an OAuth page — and minting a connect ticket for it would drop
// a bearer capability into the application's error channel and its logs, where
// it is of no use to the only party who can redeem it. Whose account a server's
// instance uses is settled on that instance instead: an administrator connects a
// shared account there, or the caller names the person it is acting for.
type ApplicationNotConnectedError struct {
	Provider string
	Registry string
	// Shared marks the instance whose account serves every caller. Nobody
	// calling can connect that one — telling them to link their own would send
	// them somewhere that changes nothing.
	Shared bool
}

func (e *ApplicationNotConnectedError) Error() string {
	server := e.Registry
	if server == "" {
		server = e.Provider
	}
	if e.Shared {
		return fmt.Sprintf(
			"mcp: %q uses one shared account for every caller and nobody has connected it; "+
				"an administrator connects it in the console, on the server's instance in Registry",
			server,
		)
	}
	// Every MCP client reads this, not only the SDK, so the remedy is the header
	// itself rather than a call in one language.
	return fmt.Sprintf(
		"mcp: %q keeps one account per user, and this request carries only the application's key, "+
			"so it has no account there. Send the %s header with the id of the end user it acts for, "+
			"or have an administrator set the server's instance to a shared account",
		server, consumerdomain.EndUserHeader,
	)
}
