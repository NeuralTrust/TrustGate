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
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/version"
	"github.com/gofiber/fiber/v2"
)

type HealthHandler struct{}

func NewHealthHandler() *HealthHandler { return &HealthHandler{} }

// Liveness godoc
// @Summary      Liveness probe
// @Description  Reports whether the process is alive.
// @Tags         system
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /healthz [get]
func (h *HealthHandler) Liveness(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "healthy",
		"version": version.Version,
		"time":    time.Now().Format(time.RFC3339),
	})
}

// Readiness godoc
// @Summary      Readiness probe
// @Description  Reports whether the process is ready to serve traffic.
// @Tags         system
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /readyz [get]
func (h *HealthHandler) Readiness(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(fiber.Map{
		"status":  "ready",
		"version": version.Version,
		"time":    time.Now().Format(time.RFC3339),
	})
}
