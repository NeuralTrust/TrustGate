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
