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
	"context"
	"log/slog"
	"time"

	"github.com/NeuralTrust/TrustGate/pkg/runtimeconfig/snapshot/readmodel"
)

type compileStage string

const (
	stageRead   compileStage = "read"
	stageBuild  compileStage = "build"
	stageEncode compileStage = "encode"
	stageMerge  compileStage = "merge"
	stageHash   compileStage = "hash"
)

var compileStageOrder = []compileStage{stageRead, stageBuild, stageEncode, stageMerge, stageHash}

type compileMode string

const (
	compileModeFull compileMode = "full"
)

type compileReason string

const (
	compileReasonBoot     compileReason = "boot"
	compileReasonBackstop compileReason = "backstop"
	compileReasonSignal   compileReason = "signal"
	// compileReasonUnnamedMarker is a marker that names no gateway or catalog,
	// written by an older build or by a write that could not name its scope.
	compileReasonUnnamedMarker compileReason = "unnamed_marker"
	// compileReasonCursorReset is a cursor that could no longer trust its
	// position: rows it never read were pruned, or too many seqs went missing.
	compileReasonCursorReset compileReason = "cursor_reset"
)

// A nil *compileStages records nothing, so compile paths can time unconditionally.
type compileStages struct {
	durations map[compileStage]time.Duration
}

func newCompileStages() *compileStages {
	return &compileStages{durations: make(map[compileStage]time.Duration, len(compileStageOrder))}
}

func (s *compileStages) since(stage compileStage, start time.Time) {
	if s == nil {
		return
	}
	s.durations[stage] += time.Since(start)
}

func (s *compileStages) ran() []compileStage {
	if s == nil {
		return nil
	}
	out := make([]compileStage, 0, len(s.durations))
	for _, stage := range compileStageOrder {
		if _, ok := s.durations[stage]; ok {
			out = append(out, stage)
		}
	}
	return out
}

func (s *compileStages) logAttr() slog.Attr {
	stages := s.ran()
	attrs := make([]any, 0, len(stages))
	for _, stage := range stages {
		attrs = append(attrs, slog.Duration(string(stage), s.durations[stage]))
	}
	return slog.Group("stages", attrs...)
}

type stagedCompiler interface {
	compileAllStaged(ctx context.Context, stages *compileStages) (global *readmodel.Snapshot, scoped map[string]*readmodel.Snapshot, catalog *readmodel.Snapshot, err error)
}
