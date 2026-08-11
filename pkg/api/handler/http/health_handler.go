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
	"context"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/version"
	"github.com/gofiber/fiber/v2"
)

const readinessTimeout = 2 * time.Second

type ReadinessCheck struct {
	Name string
	Ping func(ctx context.Context) error
}

type HealthHandler struct {
	checks []ReadinessCheck
}

func NewHealthHandler(checks ...ReadinessCheck) *HealthHandler {
	return &HealthHandler{checks: checks}
}

// Liveness godoc
// @Summary      Liveness probe
// @Description  Reports whether the process is alive. Canonical path is /healthz; /health is an alias for load-balancer defaults.
// @Tags         system
// @Produce      json
// @Success      200  {object}  map[string]string
// @Router       /healthz [get]
// @Router       /health [get]
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
// @Failure      503  {object}  map[string]string
// @Router       /readyz [get]
func (h *HealthHandler) Readiness(c *fiber.Ctx) error {
	ctx, cancel := context.WithTimeout(c.Context(), readinessTimeout)
	defer cancel()

	dependencies := make(map[string]string, len(h.checks))
	ready := true
	for _, check := range h.checks {
		if err := check.Ping(ctx); err != nil {
			ready = false
			dependencies[check.Name] = "unavailable"
			continue
		}
		dependencies[check.Name] = "ok"
	}

	status := fiber.StatusOK
	state := "ready"
	if !ready {
		status = fiber.StatusServiceUnavailable
		state = "not_ready"
	}
	return c.Status(status).JSON(fiber.Map{
		"status":       state,
		"version":      version.Version,
		"time":         time.Now().Format(time.RFC3339),
		"dependencies": dependencies,
	})
}
