package middleware

import "github.com/gofiber/fiber/v2"

type Middleware interface {
	Middleware() fiber.Handler
}

type Transport struct {
	Middlewares []Middleware
}

func NewTransport(middlewares ...Middleware) *Transport {
	return &Transport{Middlewares: middlewares}
}

func (t *Transport) GetMiddlewares() []fiber.Handler {
	handlers := make([]fiber.Handler, 0, len(t.Middlewares))
	for _, m := range t.Middlewares {
		handlers = append(handlers, m.Middleware())
	}
	return handlers
}

func (t *Transport) RegisterMiddleware(m Middleware) {
	t.Middlewares = append(t.Middlewares, m)
}
