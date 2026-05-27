// Package router declares the ServerRouter contract wired into BaseServer.
package router

import "github.com/gofiber/fiber/v2"

// ServerRouter attaches routes to a Fiber app.
type ServerRouter interface {
	BuildRoutes(router *fiber.App) error
}
