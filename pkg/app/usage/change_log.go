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

package usage

import "sort"

// changeLogSlack keeps a small log from being compacted on almost every write.
const changeLogSlack = 1024

// changeLog numbers writes so a reader can ask which tenants changed after
// the last write it saw. Each tenant keeps only its latest entry; stale ones
// are dropped once they outnumber the live ones, so the log stays within
// about twice the number of tenants. It is not safe for concurrent use.
type changeLog struct {
	seq     uint64
	at      map[string]uint64
	entries []loggedChange
}

type loggedChange struct {
	seq      uint64
	tenantID string
}

func newChangeLog() changeLog {
	return changeLog{at: make(map[string]uint64)}
}

// record logs a write to tenantID and returns its seq.
func (l *changeLog) record(tenantID string) uint64 {
	l.seq++
	l.at[tenantID] = l.seq
	l.entries = append(l.entries, loggedChange{seq: l.seq, tenantID: tenantID})
	if len(l.entries) > 2*len(l.at)+changeLogSlack {
		l.compact()
	}
	return l.seq
}

// since lists the tenants written after cursor, oldest write first and each
// once, and returns the cursor of the latest write.
func (l *changeLog) since(cursor uint64) ([]string, uint64) {
	start := sort.Search(len(l.entries), func(i int) bool { return l.entries[i].seq > cursor })
	var tenants []string
	for _, change := range l.entries[start:] {
		if l.at[change.tenantID] == change.seq {
			tenants = append(tenants, change.tenantID)
		}
	}
	return tenants, max(cursor, l.seq)
}

// tenantSince reports whether tenantID was written after cursor, and returns
// the cursor of the latest write.
func (l *changeLog) tenantSince(cursor uint64, tenantID string) (bool, uint64) {
	return l.at[tenantID] > cursor, max(cursor, l.seq)
}

func (l *changeLog) compact() {
	live := l.entries[:0]
	for _, change := range l.entries {
		if l.at[change.tenantID] == change.seq {
			live = append(live, change)
		}
	}
	clear(l.entries[len(live):])
	l.entries = live
}
