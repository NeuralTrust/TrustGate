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
	"errors"
	"io/fs"
	"strings"

	appcatalog "github.com/NeuralTrust/TrustGate/pkg/app/catalog"
	"github.com/gofiber/fiber/v2"
)

const brandCacheControl = "public, max-age=86400, immutable"

func ServeBrandAsset(c *fiber.Ctx) error {
	name := strings.TrimPrefix(c.Params("*"), "/")
	data, contentType, err := appcatalog.ReadBrandIcon(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fiber.ErrNotFound
		}
		return err
	}
	c.Set(fiber.HeaderContentType, contentType)
	c.Set(fiber.HeaderCacheControl, brandCacheControl)
	return c.Status(fiber.StatusOK).Send(data)
}
