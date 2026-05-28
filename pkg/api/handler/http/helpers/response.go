package helpers

import "github.com/gofiber/fiber/v2"

// WriteCreated sends 201 Created with the body as JSON.
func WriteCreated(c *fiber.Ctx, body any) error {
	return c.Status(fiber.StatusCreated).JSON(body)
}

// WriteOK sends 200 OK with the body as JSON.
func WriteOK(c *fiber.Ctx, body any) error {
	return c.Status(fiber.StatusOK).JSON(body)
}

// WriteNoContent sends 204 No Content with an empty body.
func WriteNoContent(c *fiber.Ctx) error {
	return c.SendStatus(fiber.StatusNoContent)
}

// ListEnvelope is the canonical shape returned by every admin listing
// endpoint. `Items` is generic at the JSON level; each handler builds
// the concrete typed slice and passes it in.
type ListEnvelope struct {
	Items any `json:"items"`
	Page  int `json:"page"`
	Size  int `json:"size"`
	Total int `json:"total"`
}

// WriteListEnvelope sends 200 OK wrapping items + pagination metadata.
func WriteListEnvelope(c *fiber.Ctx, items any, page, size, total int) error {
	return c.Status(fiber.StatusOK).JSON(ListEnvelope{
		Items: items,
		Page:  page,
		Size:  size,
		Total: total,
	})
}
