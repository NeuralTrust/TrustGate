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
	"mime"
	"net/http"
	"strconv"
	"time"

	appoauth "github.com/NeuralTrust/TrustGate/pkg/app/oauth"
	"github.com/gofiber/fiber/v2"
)

// ConnectSourceResolver names the caller a connect attempt is rate-limited by,
// from the peer address and whatever the proxy in front forwarded.
type ConnectSourceResolver func(peer, forwardedFor string) string

func isFormURLEncoded(contentType string) bool {
	mediaType, _, err := mime.ParseMediaType(contentType)
	return err == nil && mediaType == fiber.MIMEApplicationForm
}

// writeAPIKeyConnectRateLimited answers a throttled connect attempt with a
// whole-second Retry-After, rounded up so a client that waits exactly that long
// is not refused again.
func writeAPIKeyConnectRateLimited(c *fiber.Ctx, exceeded *appoauth.ConnectRateLimitExceeded) error {
	retryAfter := exceeded.RetryAfter / time.Second
	if exceeded.RetryAfter%time.Second != 0 {
		retryAfter++
	}
	if retryAfter < 1 {
		retryAfter = 1
	}
	c.Set(fiber.HeaderRetryAfter, strconv.FormatInt(int64(retryAfter), 10))
	return writeAPIKeyConnectStatus(c, fiber.StatusTooManyRequests)
}

func writeAPIKeyConnectStatus(c *fiber.Ctx, status int) error {
	return c.Status(status).SendString(http.StatusText(status))
}
