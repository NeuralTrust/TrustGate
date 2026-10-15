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
	"log/slog"

	apppolicy "github.com/NeuralTrust/TrustGate/pkg/app/policy"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/policy"
	"github.com/gofiber/fiber/v2"
)

// overlapWarnings resolves the non-blocking warnings for a policy whose write
// already succeeded. A failure computing them is logged and yields none: a
// successful write must not turn into an error response.
func overlapWarnings(c *fiber.Ctx, warner apppolicy.Warner, p *domain.Policy) []string {
	warnings, err := warner.Overlaps(c.UserContext(), p)
	if err != nil {
		slog.Default().LogAttrs(c.UserContext(), slog.LevelWarn, "policy overlap warnings unavailable",
			slog.String("error", err.Error()),
			slog.String("policy_id", p.ID.String()),
			slog.String("method", c.Method()),
			slog.String("path", c.Path()),
		)
		return nil
	}
	return warnings
}
