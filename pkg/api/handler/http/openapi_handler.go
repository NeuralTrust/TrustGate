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

package http

import (
	"github.com/NeuralTrust/TrustGate/docs"
	"github.com/gofiber/fiber/v2"
)

type OpenAPIHandler struct{}

func NewOpenAPIHandler() *OpenAPIHandler { return &OpenAPIHandler{} }

// Handle serves the OpenAPI 3 document. The spec declares `servers: [{"url": "/"}]`,
// so clients that resolve it relative to this URL reach the host they fetched it from.
func (h *OpenAPIHandler) Handle(c *fiber.Ctx) error {
	c.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)
	return c.Status(fiber.StatusOK).Send(docs.OpenAPIJSON)
}
