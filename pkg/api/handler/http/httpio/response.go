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

package httpio

import "github.com/gofiber/fiber/v2"

func WriteCreated(c *fiber.Ctx, body any) error {
	return c.Status(fiber.StatusCreated).JSON(body)
}
func WriteOK(c *fiber.Ctx, body any) error {
	return c.Status(fiber.StatusOK).JSON(body)
}
func WriteNoContent(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}

type ListEnvelope struct {
	Items any `json:"items"`
	Page  int `json:"page"`
	Size  int `json:"size"`
	Total int `json:"total"`
}

func WriteListEnvelope(c *fiber.Ctx, items any, page, size, total int) error {
	return c.Status(fiber.StatusOK).JSON(ListEnvelope{
		Items: items,
		Page:  page,
		Size:  size,
		Total: total,
	})
}
