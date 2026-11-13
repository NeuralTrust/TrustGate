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

// Package request holds the request bodies of the secret store API.
package request

import (
	"fmt"
	"strings"

	appsecretstore "github.com/NeuralTrust/TrustGate/pkg/app/secretstore"
	commonerrors "github.com/NeuralTrust/TrustGate/pkg/common/errors"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/gofiber/fiber/v2"
)

// TestSecretRequest names what to test in a store. Every field is decoded,
// as in a parsed reference; without a path only authentication is tested.
type TestSecretRequest struct {
	Path    string `json:"path,omitempty" example:"ai-gateway/openai"`
	Field   string `json:"field,omitempty" example:"api_key"`
	Version string `json:"version,omitempty"`
}

// Bind parses the body, which may be empty, into a test input for store.
func Bind(c *fiber.Ctx, gatewayID ids.GatewayID, store string) (appsecretstore.TestInput, error) {
	var req TestSecretRequest
	if len(c.Body()) > 0 {
		if err := c.BodyParser(&req); err != nil {
			return appsecretstore.TestInput{}, fmt.Errorf("invalid request body: %w", commonerrors.ErrValidation)
		}
	}
	return appsecretstore.TestInput{
		GatewayID: gatewayID,
		Store:     strings.ToLower(store),
		Path:      req.Path,
		Field:     req.Field,
		Version:   req.Version,
	}, nil
}
