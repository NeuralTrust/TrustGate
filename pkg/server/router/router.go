package router

import "github.com/gofiber/fiber/v2"

type ServerRouter interface {
	BuildRoutes(router *fiber.App) error
}
