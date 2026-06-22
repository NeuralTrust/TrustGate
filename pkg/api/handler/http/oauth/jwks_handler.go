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

package oauth

import (
	"github.com/NeuralTrust/TrustGate/pkg/app/identity/sts"
	"github.com/gofiber/fiber/v2"
)

const JWKSPath = "/.well-known/jwks.json"

type JWKSHandler struct {
	signer sts.TokenSigner
}

func NewJWKSHandler(signer sts.TokenSigner) *JWKSHandler {
	return &JWKSHandler{signer: signer}
}

func (h *JWKSHandler) Handle(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(h.signer.JWKS())
}
