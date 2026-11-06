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
	"slices"
	"testing"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/app/configsyncport"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var cursorEpoch = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func gatewayMarker(seq int64, gw ids.GatewayID) configsyncport.Marker {
	return configsyncport.Marker{Seq: seq, Kind: configsyncport.MarkerGateway, GatewayID: gw}
}

func catalogMarker(seq int64) configsyncport.Marker {
	return configsyncport.Marker{Seq: seq, Kind: configsyncport.MarkerCatalog}
}

func allMarker(seq int64) configsyncport.Marker {
	return configsyncport.Marker{Seq: seq, Kind: configsyncport.MarkerAll}
}

// cycle runs one observe-and-commit against an outbox holding rows (the
// committed markers, any order) as of now.
func cycle(c *outboxCursor, rows []configsyncport.Marker, now time.Time) dirtySet {
	sorted := slices.Clone(rows)
	slices.SortFunc(sorted, func(a, b configsyncport.Marker) int { return int(a.Seq - b.Seq) })
	var (
		since  []configsyncport.Marker
		late   []configsyncport.Marker
		minSeq int64
	)
	lateSeqs := c.lateSeqs()
	for i, m := range sorted {
		if i == 0 {
			minSeq = m.Seq
		}
		if m.Seq > c.readFrom() {
			since = append(since, m)
		}
		if slices.Contains(lateSeqs, m.Seq) {
			late = append(late, m)
		}
	}
	next, dirty := c.observe(since, late, minSeq, now)
	c.commit(next)
	return dirty
}

func TestCursor_FirstReadStartsAtTheOldestRow(t *testing.T) {
	c := newOutboxCursor(time.Minute, time.Hour, 10)
	gw := ids.New[ids.GatewayKind]()

	dirty := cycle(c, []configsyncport.Marker{gatewayMarker(40, gw), catalogMarker(41)}, cursorEpoch)

	assert.Equal(t, 2, dirty.markers)
	assert.True(t, dirty.catalog)
	assert.Contains(t, dirty.gateways, gw)
	assert.False(t, dirty.full)
	assert.Equal(t, int64(41), c.readFrom())
	assert.Empty(t, c.state.gaps, "rows below the oldest one at the first read are not awaited")
}

func TestCursor_EmptyOutboxStaysUninitialised(t *testing.T) {
	c := newOutboxCursor(time.Minute, time.Hour, 10)

	dirty := cycle(c, nil, cursorEpoch)
	assert.Zero(t, dirty.markers)
	assert.Zero(t, c.readFrom())

	cycle(c, []configsyncport.Marker{allMarker(500)}, cursorEpoch)
	assert.Equal(t, int64(500), c.readFrom())
	assert.Empty(t, c.state.gaps)
}

func TestCursor_LowerSeqVisibleAfterAHigherOneIsReadOnce(t *testing.T) {
	c := newOutboxCursor(time.Minute, time.Hour, 10)
	gw4, gw5 := ids.New[ids.GatewayKind](), ids.New[ids.GatewayKind]()
	rows := []configsyncport.Marker{catalogMarker(3)}
	cycle(c, rows, cursorEpoch)

	rows = append(rows, gatewayMarker(5, gw5))
	dirty := cycle(c, rows, cursorEpoch.Add(time.Second))
	assert.Equal(t, 1, dirty.markers)
	assert.Contains(t, dirty.gateways, gw5)
	assert.Equal(t, int64(3), c.readFrom(), "the cursor holds below the missing seq 4")
	assert.Contains(t, c.state.gaps, int64(4))

	rows = append(rows, gatewayMarker(4, gw4))
	dirty = cycle(c, rows, cursorEpoch.Add(2*time.Second))
	assert.Equal(t, 1, dirty.markers, "seq 5 must not be applied twice")
	assert.Contains(t, dirty.gateways, gw4)
	assert.NotContains(t, dirty.gateways, gw5)
	assert.Equal(t, int64(5), c.readFrom())
	assert.Empty(t, c.state.gaps)
	assert.Empty(t, c.state.seen, "seen holds only seqs above the low water mark")
}

func TestCursor_RolledBackSeqExpiresIntoTheLateSet(t *testing.T) {
	c := newOutboxCursor(30*time.Second, time.Hour, 10)
	rows := []configsyncport.Marker{allMarker(1), allMarker(3)}
	cycle(c, rows, cursorEpoch)
	require.Contains(t, c.state.gaps, int64(2))
	require.Equal(t, int64(1), c.readFrom())

	cycle(c, rows, cursorEpoch.Add(31*time.Second))

	assert.Empty(t, c.state.gaps)
	assert.Contains(t, c.state.late, int64(2))
	assert.Equal(t, int64(3), c.readFrom(), "an expired gap no longer holds the cursor back")
}

func TestCursor_MarkerCommittingAfterItsGapExpiredIsReadOnTheNextCycle(t *testing.T) {
	c := newOutboxCursor(30*time.Second, time.Hour, 10)
	gw := ids.New[ids.GatewayKind]()
	rows := []configsyncport.Marker{allMarker(1), allMarker(3)}
	cycle(c, rows, cursorEpoch)
	cycle(c, rows, cursorEpoch.Add(31*time.Second))
	require.Contains(t, c.state.late, int64(2))

	rows = append(rows, gatewayMarker(2, gw))
	dirty := cycle(c, rows, cursorEpoch.Add(32*time.Second))

	assert.Equal(t, 1, dirty.markers)
	assert.Contains(t, dirty.gateways, gw)
	assert.False(t, dirty.full, "a slow transaction is picked up incrementally, not left to the backstop")
	assert.Empty(t, c.state.late)

	dirty = cycle(c, rows, cursorEpoch.Add(33*time.Second))
	assert.Zero(t, dirty.markers, "a late marker is applied once")
}

func TestCursor_LateSetOverItsBoundForcesAFullCompile(t *testing.T) {
	c := newOutboxCursor(time.Second, time.Hour, 2)
	rows := []configsyncport.Marker{allMarker(1), allMarker(5)}
	cycle(c, rows, cursorEpoch)
	require.Len(t, c.state.gaps, 3)

	dirty := cycle(c, rows, cursorEpoch.Add(2*time.Second))

	assert.True(t, dirty.full)
	assert.Equal(t, compileReasonCursorReset, dirty.fullReason)
	assert.Empty(t, c.state.late)
	assert.Equal(t, int64(5), c.readFrom())
}

func TestCursor_LateSeqsAgeOutWithTheRetention(t *testing.T) {
	c := newOutboxCursor(time.Second, time.Minute, 10)
	rows := []configsyncport.Marker{allMarker(1), allMarker(3)}
	cycle(c, rows, cursorEpoch)
	cycle(c, rows, cursorEpoch.Add(2*time.Second))
	require.Contains(t, c.state.late, int64(2))

	cycle(c, rows, cursorEpoch.Add(2*time.Minute))
	assert.Empty(t, c.state.late)
}

func TestCursor_RowsPrunedBeforeTheyWereReadForceAFullCompile(t *testing.T) {
	c := newOutboxCursor(time.Minute, time.Hour, 10)
	cycle(c, []configsyncport.Marker{allMarker(10)}, cursorEpoch)
	require.Equal(t, int64(10), c.readFrom())

	dirty := cycle(c, []configsyncport.Marker{catalogMarker(20)}, cursorEpoch.Add(time.Second))

	assert.True(t, dirty.full)
	assert.Equal(t, compileReasonCursorReset, dirty.fullReason)
	assert.True(t, dirty.catalog)
	assert.Equal(t, int64(20), c.readFrom())
	assert.Empty(t, c.state.gaps)
}

func TestCursor_PruneOfKnownGapsIsNotAReset(t *testing.T) {
	c := newOutboxCursor(time.Minute, time.Hour, 10)
	rows := []configsyncport.Marker{allMarker(1), allMarker(4)}
	cycle(c, rows, cursorEpoch)
	require.Equal(t, int64(1), c.readFrom())

	dirty := cycle(c, []configsyncport.Marker{allMarker(4)}, cursorEpoch.Add(time.Second))

	assert.Equal(t, compileReason(""), dirty.fullReason, "rows 2 and 3 were gaps already, so nothing unread was pruned")
}

func TestCursor_MarkerWithoutAKindForcesAFullCompile(t *testing.T) {
	c := newOutboxCursor(time.Minute, time.Hour, 10)
	gw := ids.New[ids.GatewayKind]()

	dirty := cycle(c, []configsyncport.Marker{gatewayMarker(1, gw), allMarker(2)}, cursorEpoch)

	assert.True(t, dirty.full)
	assert.Equal(t, compileReasonUnnamedMarker, dirty.fullReason)
	assert.Contains(t, dirty.gateways, gw)
}

func TestCursor_AnUncommittedCycleReadsTheSameMarkersAgain(t *testing.T) {
	c := newOutboxCursor(time.Minute, time.Hour, 10)
	cycle(c, []configsyncport.Marker{allMarker(1)}, cursorEpoch)
	gw := ids.New[ids.GatewayKind]()
	rows := []configsyncport.Marker{allMarker(1), gatewayMarker(2, gw)}

	_, dirty := c.observe([]configsyncport.Marker{gatewayMarker(2, gw)}, nil, 1, cursorEpoch.Add(time.Second))
	require.Equal(t, 1, dirty.markers)
	assert.Equal(t, int64(1), c.readFrom(), "observe alone must not move the cursor")

	dirty = cycle(c, rows, cursorEpoch.Add(2*time.Second))
	assert.Equal(t, 1, dirty.markers)
	assert.Contains(t, dirty.gateways, gw)
}
