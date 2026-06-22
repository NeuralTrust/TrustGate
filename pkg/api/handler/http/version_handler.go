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
	"github.com/NeuralTrust/TrustGate/pkg/version"
	"github.com/gofiber/fiber/v2"
)

type VersionHandler struct{}

func NewVersionHandler() *VersionHandler { return &VersionHandler{} }

// Handle godoc
// @Summary      Build version
// @Description  Returns build/version information for the running binary.
// @Tags         system
// @Produce      json
// @Success      200  {object}  version.Info
// @Router       /__/version [get]
func (h *VersionHandler) Handle(c *fiber.Ctx) error {
	return c.Status(fiber.StatusOK).JSON(version.GetInfo())
}
