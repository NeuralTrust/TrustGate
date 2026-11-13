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

package proxy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

func TestSecretUnavailableIs503WithoutDetails(t *testing.T) {
	t.Parallel()
	status, body := mapProxyError(fmt.Errorf("registry r: %w", registrydomain.ErrSecretUnavailable))
	if status != fiber.StatusServiceUnavailable || body.Error != "secret_unavailable" {
		t.Fatalf("status %d body %+v", status, body)
	}
	if strings.Contains(body.Message, "registry r") || strings.Contains(body.Message, "secret://") {
		t.Fatalf("message %q leaks details", body.Message)
	}
}
