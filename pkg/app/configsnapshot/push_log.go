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
	"bytes"
	"log/slog"
	"sort"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
)

// maxFragmentLogLines caps the per-fragment lines of one push or pull; the
// summary line still counts every fragment.
const maxFragmentLogLines = 20

type pushedFragment struct {
	digest [32]byte
	size   int
}

type pushStats struct {
	fragments     int
	pushed        []pushedFragment
	alreadyExists int
	pushedBytes   int
	scopes        int
	scopesChanged int
}

// diffPush compares a layered publish with the one before it: fragments the
// previous generation did not hold are pushed, the rest already exist. With no
// previous generation every fragment is pushed.
func diffPush(previous, next *Layered) pushStats {
	stats := pushStats{fragments: len(next.Fragments), scopes: len(next.Scoped)}
	for digest, raw := range next.Fragments {
		if previous != nil {
			if _, ok := previous.Fragments[digest]; ok {
				stats.alreadyExists++
				continue
			}
		}
		stats.pushed = append(stats.pushed, pushedFragment{digest: digest, size: len(raw)})
		stats.pushedBytes += len(raw)
	}
	sort.Slice(stats.pushed, func(i, j int) bool {
		return bytes.Compare(stats.pushed[i].digest[:], stats.pushed[j].digest[:]) < 0
	})
	for scope, manifest := range next.Scoped {
		if previous == nil || previous.Scoped[scope].Version != manifest.Version {
			stats.scopesChanged++
		}
	}
	return stats
}

// logPush reports a layered publish the way docker push does: one line per
// new fragment, up to maxFragmentLogLines, then a summary.
func (d *Dispatcher) logPush(previous, next *Layered) {
	stats := diffPush(previous, next)
	for i, fragment := range stats.pushed {
		if i == maxFragmentLogLines {
			break
		}
		d.logger.Info("push fragment",
			slog.String("component", component),
			slog.String("status", "Pushed"),
			slog.String("fragment", configsyncport.ShortDigest(fragment.digest)),
			slog.Int("bytes", fragment.size))
	}
	d.logger.Info("push complete",
		slog.String("component", component),
		slog.String("version", next.Global.Version),
		slog.Int("fragments", stats.fragments),
		slog.Int("pushed", len(stats.pushed)),
		slog.Int("already_exists", stats.alreadyExists),
		slog.Int("pushed_bytes", stats.pushedBytes),
		slog.Int("scopes_changed", stats.scopesChanged),
		slog.Int("scopes", stats.scopes))
}
