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

package configsnapshot

import (
	"log/slog"
	"strings"

	"github.com/gofiber/fiber/v2"
)

const (
	contentTypeProtobuf  = "application/x-protobuf"
	headerInstanceID     = "X-Instance-Id"
	headerAppliedVersion = "X-Applied-Version"
	component            = "configsnapshot"
)

type SnapshotSource interface {
	Snapshot() (raw []byte, version string, ok bool)
}

type Handler struct {
	source SnapshotSource
	logger *slog.Logger
}

func NewHandler(source SnapshotSource, logger *slog.Logger) *Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return &Handler{source: source, logger: logger}
}

func (h *Handler) Get(c *fiber.Ctx) error {
	h.logPull(c)

	raw, version, ok := h.source.Snapshot()
	if !ok {
		return c.SendStatus(fiber.StatusServiceUnavailable)
	}

	if match := strings.Trim(c.Get(fiber.HeaderIfNoneMatch), `"`); match != "" && match == version {
		return c.SendStatus(fiber.StatusNotModified)
	}

	c.Set(fiber.HeaderETag, `"`+version+`"`)
	c.Set(fiber.HeaderContentType, contentTypeProtobuf)
	return c.Status(fiber.StatusOK).Send(raw)
}

func (h *Handler) logPull(c *fiber.Ctx) {
	instanceID := c.Get(headerInstanceID)
	appliedVersion := c.Get(headerAppliedVersion)
	if instanceID == "" && appliedVersion == "" {
		return
	}
	h.logger.Info("config snapshot pull",
		slog.String("component", component),
		slog.String("instance_id", instanceID),
		slog.String("applied_version", appliedVersion),
	)
}
