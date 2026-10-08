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

package proxy

import (
	"context"
	"log/slog"
	"strings"

	appplugins "github.com/NeuralTrust/TrustGate/pkg/app/plugins"
	"github.com/NeuralTrust/TrustGate/pkg/infra/providers/adapter"
)

type nativeToolBlock struct {
	events []int
	deltas []int
	clean  bool
}

func (g *streamGuard) trackTool(ev *streamEvent) {
	switch ev.tool {
	case toolStart:
		if !g.toolOpen {
			g.toolOpen, g.toolOpenIdx, g.toolSince = true, ev.toolIndex, g.now()
		}
	case toolStop:
		if g.toolOpen && (ev.toolIndex == g.toolOpenIdx || ev.toolIndex < 0 || g.toolOpenIdx < 0) {
			g.toolOpen = false
		}
	}
}

func (g *streamGuard) holdsTool() bool {
	return g.native && g.toolOpen && g.now().Sub(g.toolSince) < g.cfg.nativeToolHold
}

func (g *streamGuard) toolBlocks() []nativeToolBlock {
	var (
		out []nativeToolBlock
		cur *nativeToolBlock
		idx int
	)
	for i := g.releasedIdx; i < len(g.produced); i++ {
		ev := g.produced[i]
		switch {
		case cur == nil && ev.tool == toolStart:
			cur = &nativeToolBlock{clean: true, events: []int{i}}
			idx = ev.toolIndex
		case cur == nil:
		case ev.tool == toolStop && (ev.toolIndex == idx || ev.toolIndex < 0 || idx < 0):
			cur.events = append(cur.events, i)
			out = append(out, *cur)
			cur = nil
		case ev.tool == toolDelta && (ev.toolIndex == idx || ev.toolIndex < 0 || idx < 0):
			cur.events = append(cur.events, i)
			cur.deltas = append(cur.deltas, i)
		default:
			if ev.text != "" || ev.reasoning != "" || len(ev.toolCalls) > 0 || ev.tool != toolNone {
				cur.clean = false
			}
			cur.events = append(cur.events, i)
		}
	}
	return out
}

type toolVerdict struct {
	outcome *appplugins.SegmentOutcome
	stop    bool
	failed  bool
}

func (g *streamGuard) toolSegment(input string) appplugins.StreamSegment {
	g.seq++
	return appplugins.StreamSegment{StreamID: g.streamID, Seq: g.seq, Text: input, Accumulated: input}
}

// inspectTools asks the chain about each complete tool call of the held window
// and applies what it answers. The input of a tool call arrives as JSON text cut
// anywhere across frames, so a policy reading the text of the stream never sees it
// whole: for ConverseStream and the Anthropic events of an InvokeModel stream the
// guard holds the call from its start frame to its stop frame, joins the input and
// asks the chain about it as a text of its own. A mask is written back into the
// held frames, all of it in the first frame that carried input and the later ones
// left in place with an empty input; nothing of the call is released before its
// stop frame. A block verdict, or a mask that cannot be written back and checked,
// stops the stream. A call whose inspection fails follows the stream's on_error:
// fail_closed stops the stream, anything else releases the call as it came.
//
// Every other family, and any call the hold could not cover, is not understood
// well enough to edit, so a mask on a window that holds one fails open as any mask
// a native stream cannot apply does (see applyTransform).
func (g *streamGuard) inspectTools(ctx context.Context) toolVerdict {
	if !g.native {
		return toolVerdict{}
	}
	for _, b := range g.toolBlocks() {
		if !b.clean || g.produced[b.events[0]].toolHandled {
			continue
		}
		var raw strings.Builder
		for _, di := range b.deltas {
			for _, tc := range g.produced[di].toolCalls {
				raw.WriteString(tc.ArgumentsDelta)
			}
		}
		if raw.Len() == 0 {
			g.markToolHandled(b)
			continue
		}
		view, normalised := adapter.NormalizeToolInput(raw.String())
		outcome, err := g.call(ctx, g.toolSegment(view))
		if err != nil {
			g.failures++
			if g.cfg.onError == streamFailClosed {
				return toolVerdict{stop: true, failed: true}
			}
			if outcome != nil && outcome.HasTransform {
				if cause := g.applyToolMask(b, view, outcome.Transformed, normalised); cause != "" {
					if outcome.MaskFailureBlock {
						return toolVerdict{outcome: outcome, stop: true}
					}
					g.maskFailedOpen(ctx, cause)
				}
			}
			g.degrade(blockFailureReason(err))
			if g.logger != nil {
				g.logger.Warn("tool call inspection failed; releasing the call",
					slog.String("error", err.Error()))
			}
			g.markToolHandled(b)
			if g.gate != nil && g.failures >= maxConsecutiveFailures {
				g.retire(fallbackSegmentationUnavail)
				return toolVerdict{}
			}
			continue
		}
		g.failures = 0
		if outcome != nil && outcome.Block {
			return toolVerdict{outcome: outcome, stop: true}
		}
		if outcome != nil && outcome.HasTransform {
			if cause := g.applyToolMask(b, view, outcome.Transformed, normalised); cause != "" {
				// The mask cannot be written into the held frames and read back: the
				// call goes through as it came and the outcome is recorded, unless the
				// policy asked for on_mask_failure: block.
				if outcome.MaskFailureBlock {
					return toolVerdict{outcome: outcome, stop: true}
				}
				g.maskFailedOpen(ctx, cause)
			}
		}
		g.markToolHandled(b)
	}
	g.flagUninspectedTools()
	return toolVerdict{}
}

// markToolHandled records that a call was inspected, and takes it out of the tool
// calls later segments carry: the chain has read it as a text of its own, and
// reading it again through ToolCalls would inspect it twice.
func (g *streamGuard) markToolHandled(b nativeToolBlock) {
	for _, i := range b.events {
		g.produced[i].toolHandled = true
	}
	// Only the calls this block carried change: each is rebuilt from its own
	// events that no tool pass has handled, never from the whole stream.
	touched := map[int]struct{}{}
	for _, i := range b.events {
		for _, tc := range g.produced[i].toolCalls {
			touched[tc.Index] = struct{}{}
		}
	}
	for idx := range touched {
		var remaining []adapter.StreamToolCallDelta
		for _, ev := range g.toolEvents[idx] {
			if ev.toolHandled {
				continue
			}
			for _, tc := range ev.toolCalls {
				if tc.Index == idx {
					remaining = append(remaining, tc)
				}
			}
		}
		if len(remaining) == 0 {
			g.unhandledTools.drop(idx)
			continue
		}
		g.unhandledTools.reset(idx)
		g.unhandledTools.merge(remaining)
	}
}

func (g *streamGuard) trackToolEvent(ev *streamEvent) {
	var last = -1
	for _, tc := range ev.toolCalls {
		if tc.Index == last {
			continue
		}
		last = tc.Index
		if g.toolEvents == nil {
			g.toolEvents = map[int][]*streamEvent{}
		}
		if events := g.toolEvents[tc.Index]; len(events) == 0 || events[len(events)-1] != ev {
			g.toolEvents[tc.Index] = append(events, ev)
		}
	}
}

// flagUninspectedTools makes visible the tool calls about to be released without
// the chain having read their input as a text of its own: a call that outgrew the
// hold in time or in bytes, one the stream ended before closing, one with another
// frame inside it, one whose start was released earlier, and a family whose tool
// calls are not understood. They still reach the chain through the ToolCalls of
// the segments, as they always did. The stream is marked degraded, and the cause
// is logged once.
func (g *streamGuard) flagUninspectedTools() {
	var unclean map[int]struct{}
	for i := g.releasedIdx; i < len(g.produced); i++ {
		ev := g.produced[i]
		if ev.toolHandled || len(ev.toolCalls) == 0 {
			continue
		}
		if unclean == nil {
			unclean = map[int]struct{}{}
			for _, b := range g.toolBlocks() {
				if !b.clean {
					for _, e := range b.events {
						unclean[e] = struct{}{}
					}
				}
			}
		}
		cause := "partial"
		_, inUnclean := unclean[i]
		switch {
		case g.toolOpen && (g.exhausted || g.srcErr != nil || g.terminal):
			cause = "no_stop"
		case g.toolOpen && g.now().Sub(g.toolSince) >= g.cfg.nativeToolHold:
			cause = "time"
		case g.toolOpen:
			cause = "size"
		case ev.tool == toolNone:
			cause = "unsupported"
		case inUnclean:
			cause = "unclean"
		}
		g.degrade(degradeToolInputUninspected)
		if !g.toolUninspectedLogged && g.logger != nil {
			g.toolUninspectedLogged = true
			g.logger.Warn("tool call released without inspecting its input",
				slog.String("cause", cause),
				slog.String("format", string(g.source)))
		}
		return
	}
}

// applyToolMask writes a masked tool input into the held frames of the call and
// returns "", or the cause it could not. Nothing is changed until the rebuilt
// frames have been read back: the input they carry, joined and unescaped, must be
// the masked one, and none of the removed text of three characters or more may be
// anywhere in them.
func (g *streamGuard) applyToolMask(b nativeToolBlock, view, masked string, normalised bool) adapter.MaskCause {
	if !normalised {
		return adapter.MaskCauseToolInput
	}
	input, ok := adapter.MaskToolInput(view, masked)
	if !ok {
		return adapter.MaskCauseToolInput
	}
	hunks, ok := adapter.DiffText(view, masked)
	if !ok {
		return adapter.MaskCauseToolInput
	}
	frames := make(map[int][]byte, len(b.deltas))
	var joined strings.Builder
	carrier := -1
	for _, di := range b.deltas {
		ev := g.produced[di]
		if len(ev.lines) != 1 || len(ev.toolCalls) > 1 {
			return adapter.MaskCauseToolFrames
		}
		if len(ev.toolCalls) == 0 {
			if current, ok := adapter.BedrockFrameToolInput(ev.lines[0]); !ok || current != "" {
				return adapter.MaskCauseToolFrames
			}
			frames[di] = ev.lines[0]
			continue
		}
		fragment := ""
		if carrier < 0 {
			carrier = di
			fragment = input
		}
		frame := ev.lines[0]
		if current, ok := adapter.BedrockFrameToolInput(frame); !ok {
			return adapter.MaskCauseToolFrames
		} else if current != fragment {
			if frame, ok = adapter.RewriteBedrockFrameToolInput(frame, fragment); !ok {
				return adapter.MaskCauseToolFrames
			}
		}
		got, ok := adapter.BedrockFrameToolInput(frame)
		if !ok {
			return adapter.MaskCauseToolFrames
		}
		joined.WriteString(got)
		frames[di] = frame
		for _, h := range hunks {
			from := view[h.Start:h.End]
			if len(from) >= 3 && adapter.BedrockFrameHolds(frame, from) {
				return adapter.MaskCauseLeak
			}
		}
	}
	if carrier < 0 || joined.String() != input {
		return adapter.MaskCauseShape
	}
	for _, h := range hunks {
		if from := view[h.Start:h.End]; len(from) >= 3 && adapter.StringHolds(joined.String(), from) {
			return adapter.MaskCauseLeak
		}
	}
	for _, di := range b.deltas {
		ev := g.produced[di]
		ev.lines[0] = frames[di]
		if len(ev.toolCalls) == 0 {
			continue
		}
		if di == carrier {
			ev.toolCalls[0].ArgumentsDelta = input
		} else {
			ev.toolCalls[0].ArgumentsDelta = ""
		}
	}
	g.tools = toolCallDigest{}
	for _, ev := range g.produced {
		g.tools.merge(ev.toolCalls)
	}
	return ""
}
