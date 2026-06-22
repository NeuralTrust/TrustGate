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

package oauth

import (
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/api/handler/http/helpers"
	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

const WellKnownProtectedResourcePath = "/.well-known/oauth-protected-resource"

type ProtectedResourceHandler struct {
	metadata appoauth.MetadataService
}

func NewProtectedResourceHandler(metadata appoauth.MetadataService) *ProtectedResourceHandler {
	return &ProtectedResourceHandler{metadata: metadata}
}

func (h *ProtectedResourceHandler) Handle(c *fiber.Ctx) error {
	resource := c.BaseURL()
	if suffix := strings.Trim(c.Params("*"), "/"); suffix != "" {
		resource += "/" + suffix
	}
	meta, err := h.metadata.ProtectedResource(c.UserContext(), c.BaseURL(), resource)
	if err != nil {
		return helpers.WriteError(c, err)
	}
	return helpers.WriteOK(c, meta)
}
