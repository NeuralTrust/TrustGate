package middleware

import "github.com/gofiber/fiber/v2"

type Middleware interface {
	Middleware() fiber.Handler
}

type Transport struct {
	Middlewares []Middleware
}

func NewTransport(middlewares ...Middleware) *Transport {
	return &Transport{
		Middlewares: middlewares,
	}
}

func (t *Transport) GetMiddlewares() []interface{} {
	var handlers []interface{}
	for _, middleware := range t.Middlewares {
		handlers = append(handlers, middleware.Middleware())
	}
	return handlers
}

func (t *Transport) RegisterMiddleware(middleware Middleware) {
	t.Middlewares = append(t.Middlewares, middleware)
}
