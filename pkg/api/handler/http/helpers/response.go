package helpers

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
