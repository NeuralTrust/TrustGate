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

package grpc

import (
	"context"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
)

const (
	pullComponent = "configsync"
	// maxFragmentLogLines caps the per-fragment lines of one pull; the summary
	// line still counts every fragment.
	maxFragmentLogLines = 20

	pullStatusUpToDate   = "Snapshot is up to date"
	pullStatusDownloaded = "Downloaded newer snapshot"

	fallbackUnimplemented = "unimplemented"
	fallbackFragmentGone  = "fragment_gone"
)

// pullStats counts what one layered pull did, for its docker-style summary.
type pullStats struct {
	fragments     int
	alreadyExists int
	pulled        int
	pulledBytes   int64
	restarts      int
}

func (c *Client) logAlreadyExists(ctx context.Context, digest [32]byte, size int) {
	if !c.logger.Enabled(ctx, slog.LevelDebug) {
		return
	}
	c.logger.Debug("pull fragment",
		slog.String("component", pullComponent),
		slog.String("status", "Already exists"),
		slog.String("fragment", configsyncport.ShortDigest(digest)),
		slog.Int("bytes", size))
}

func (c *Client) logPulledFragment(stats *pullStats, digest [32]byte, size int) {
	stats.pulled++
	stats.pulledBytes += int64(size)
	if stats.pulled > maxFragmentLogLines {
		return
	}
	c.logger.Info("pull fragment",
		slog.String("component", pullComponent),
		slog.String("status", "Pull complete"),
		slog.String("fragment", configsyncport.ShortDigest(digest)),
		slog.Int("bytes", size))
}

func (c *Client) logUpToDate(mode, version string) {
	c.logger.Info("pull complete",
		slog.String("component", pullComponent),
		slog.String("mode", mode),
		slog.String("status", pullStatusUpToDate),
		slog.String("version", version))
}

func (c *Client) logLayeredPull(version string, stats pullStats, total int, started time.Time) {
	c.logger.Info("pull complete",
		slog.String("component", pullComponent),
		slog.String("mode", "layered"),
		slog.String("status", pullStatusDownloaded),
		slog.String("version", version),
		slog.Int("fragments", stats.fragments),
		slog.Int("already_exists", stats.alreadyExists),
		slog.Int("pulled", stats.pulled),
		slog.Int64("pulled_bytes", stats.pulledBytes),
		slog.Int("total_bytes", total),
		slog.Duration("duration", time.Since(started)),
		slog.Int("restarts", stats.restarts))
}

// logFullPull reports a single-blob pull; fallbackReason is set when a layered
// pull gave way to it.
func (c *Client) logFullPull(version string, total int, started time.Time, fallbackReason string) {
	attrs := []any{
		slog.String("component", pullComponent),
		slog.String("mode", "full"),
		slog.String("status", pullStatusDownloaded),
		slog.String("version", version),
		slog.Int("pulled_bytes", total),
		slog.Int("total_bytes", total),
		slog.Duration("duration", time.Since(started)),
	}
	if fallbackReason != "" {
		attrs = append(attrs, slog.String("fallback_reason", fallbackReason))
	}
	c.logger.Info("pull complete", attrs...)
}
