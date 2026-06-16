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

// Package router declares the ServerRouter contract wired into BaseServer.
package router

import "github.com/gofiber/fiber/v2"

// ServerRouter attaches routes to a Fiber app.
type ServerRouter interface {
	BuildRoutes(router *fiber.App) error
}
