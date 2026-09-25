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

package adapter

import (
	"encoding/json"
	"strconv"
	"strings"
)

// CacheTTL is a requested prompt-cache lifetime; empty means the provider default.
type CacheTTL string

const (
	// CacheTTL5m is the five-minute cache lifetime.
	CacheTTL5m CacheTTL = "5m"
	// CacheTTL1h is the one-hour cache lifetime.
	CacheTTL1h CacheTTL = "1h"
)

// CanonicalCacheBreakpoint marks a prompt-cache boundary in a segment (system,
// tool or message). A nil breakpoint means no intent; the zero value puts the
// boundary at the end of the segment.
//
// The unexported fields are set by the Anthropic, OpenAI Chat and Responses
// decoders, which join a segment's text blocks with "\n". They let the
// encoders of those formats split the text back at the marked block even
// after a plugin changed its length. Encoders for other targets ignore them.
//
// Only a change in the segment's newline count is detected. A rewrite that
// moves a newline across the boundary while keeping the count splits the text
// at the wrong line. The fields are tied to the segment the marker was decoded
// from, so a plugin that copies or moves a message must clone its Cache rather
// than share the pointer, and must not expect clientLast or the boundary to
// follow the message to its new position.
type CanonicalCacheBreakpoint struct {
	TTL CacheTTL `json:"ttl,omitempty"`

	// inText reports that the marked block was a text block of the segment,
	// so the boundary is the "\n" that followed it rather than the segment's
	// end.
	inText bool
	// newline counts the "\n" in the segment text before that boundary, so
	// the joiner is newline number newline (from zero), or the text's end
	// when newline equals newlines.
	newline int
	// newlines is the "\n" count of the whole segment text at decode time. A
	// different count at encode time means a plugin added or removed lines
	// and the boundary can no longer be found.
	newlines int
	// clientLast reports that the client sent this marker, with this TTL, on
	// the last block of the segment.
	clientLast bool
	// raisedLast reports that the client sent this marker on the last block
	// with clientTTL and merging with an earlier 1h marker raised it.
	raisedLast bool
	clientTTL  CacheTTL
}

// CanonicalCacheOptions is request-level cache intent: the OpenAI-family
// prompt_cache_key, prompt_cache_retention and prompt_cache_options keys, and
// Auto for Anthropic's top-level automatic cache_control.
type CanonicalCacheOptions struct {
	Key       string                    `json:"key,omitempty"`
	Retention string                    `json:"retention,omitempty"`
	Mode      string                    `json:"mode,omitempty"`
	Options   json.RawMessage           `json:"options,omitempty"`
	Auto      *CanonicalCacheBreakpoint `json:"auto,omitempty"`
}

func (o *CanonicalCacheOptions) empty() bool {
	return o.Key == "" && o.Retention == "" && o.Mode == "" && len(o.Options) == 0 && o.Auto == nil
}

// openAICacheOptions reads the OpenAI-family request keys; options is kept
// verbatim and its mode parsed. It returns nil when none is set.
func openAICacheOptions(key, retention string, options json.RawMessage) *CanonicalCacheOptions {
	o := &CanonicalCacheOptions{Key: key, Retention: retention}
	if len(options) > 0 && string(options) != "null" {
		o.Options = options
		var probe struct {
			Mode string `json:"mode"`
		}
		if json.Unmarshal(options, &probe) == nil {
			o.Mode = probe.Mode
		}
	}
	if o.empty() {
		return nil
	}
	return o
}

func (o *CanonicalCacheOptions) openAIOptions() json.RawMessage {
	if len(o.Options) > 0 {
		return o.Options
	}
	if o.Mode == "" {
		return nil
	}
	raw, err := json.Marshal(map[string]string{"mode": o.Mode})
	if err != nil {
		return nil
	}
	return raw
}

type cacheProfile struct {
	tools, system, messages, ttl1h bool
	max                            int
	key, retention, options, auto  bool
	// implicitSlot reports that the provider spends one of the max writes on
	// its own breakpoint unless prompt_cache_options.mode is "explicit".
	implicitSlot bool
}

// cacheProfileFor returns what target accepts for model. GPT-5.6 and later
// take breakpoints and prompt_cache_options and no longer take
// prompt_cache_retention; earlier models answer 400 to the first two. xAI
// Chat keys its cache by the x-grok-conv-id header, not a body field.
func cacheProfileFor(target Format, model string) cacheProfile {
	switch target {
	case FormatAnthropic:
		return cacheProfile{tools: true, system: true, messages: true, ttl1h: true, max: 4, auto: true}
	case FormatBedrock:
		return cacheProfile{tools: true, system: true, messages: true, ttl1h: true, max: 4}
	case FormatOpenAIResponses:
		p := openAICacheOptionsProfile(model)
		if p.options {
			p.system, p.messages, p.max, p.implicitSlot = true, true, 4, true
		}
		return p
	case FormatOpenAI, FormatAzure:
		return openAICacheOptionsProfile(model)
	default:
		return cacheProfile{}
	}
}

func openAICacheOptionsProfile(model string) cacheProfile {
	explicit := isGPT56OrLater(model)
	return cacheProfile{key: true, retention: !explicit, options: explicit}
}

// isGPT56OrLater reports whether model is gpt-5.6, a later gpt-5 minor or
// gpt-6 to gpt-9, with or without a vendor prefix ("openai/") or a suffix
// ("-2026-08-01", "-mini"). The major version must be one digit so Azure's
// "gpt-35-turbo" (GPT-3.5) does not match.
func isGPT56OrLater(model string) bool {
	model = strings.ToLower(model)
	if i := strings.LastIndexByte(model, '/'); i >= 0 {
		model = model[i+1:]
	}
	rest, ok := strings.CutPrefix(model, "gpt-")
	if !ok {
		return false
	}
	major, after := leadingNumber(rest)
	switch {
	case len(rest)-len(after) != 1 || major < 5:
		return false
	case major > 5:
		return true
	}
	rest = after
	minorText, ok := strings.CutPrefix(rest, ".")
	if !ok {
		return false
	}
	minor, _ := leadingNumber(minorText)
	return minor >= 6
}

func leadingNumber(s string) (int, string) {
	end := 0
	for end < len(s) && s[end] >= '0' && s[end] <= '9' {
		end++
	}
	n, err := strconv.Atoi(s[:end])
	if err != nil {
		return -1, s
	}
	return n, s[end:]
}

// laterCacheBreakpoint merges two markers of one segment into a new one: the
// later position with the longer TTL. Raising the later marker to 1h stays
// valid because every marker before a 1h one must already be 1h. A nil later
// returns earlier unchanged.
func laterCacheBreakpoint(earlier, later *CanonicalCacheBreakpoint) *CanonicalCacheBreakpoint {
	if later == nil {
		return earlier
	}
	merged := *later
	if earlier != nil && earlier.TTL == CacheTTL1h {
		merged.TTL = CacheTTL1h
	}
	return &merged
}

// normalizeCacheIntent applies the target's cache policy to intent decoded from
// another format. Encoders stay faithful, so same-format re-encodes keep the
// client's markers exactly as sent. The cap runs before the TTL walk so a
// breakpoint that is dropped never downgrades the ones that stay.
func normalizeCacheIntent(req *CanonicalRequest, target Format) {
	if req == nil {
		return
	}
	p := cacheProfileFor(target, req.Model)
	dropDisallowedCacheIntent(req, p)
	if p.implicitSlot && (req.CacheOptions == nil || req.CacheOptions.Mode != "explicit") {
		p.max--
	}

	for n := len(cacheBreakpointsInOrder(req)); p.max > 0 && n > p.max; n-- {
		if !dropEarliestCacheBreakpoint(req.Messages, func(m *CanonicalMessage) **CanonicalCacheBreakpoint { return &m.Cache }) &&
			!dropEarliestCacheBreakpoint(req.Tools, func(t *CanonicalTool) **CanonicalCacheBreakpoint { return &t.Cache }) {
			break
		}
	}

	short := false
	for _, bp := range cacheBreakpointsInOrder(req) {
		if bp.TTL == CacheTTL1h && (short || !p.ttl1h) {
			bp.TTL = CacheTTL5m
		}
		short = short || bp.TTL != CacheTTL1h
	}
}

func dropDisallowedCacheIntent(req *CanonicalRequest, p cacheProfile) {
	if !p.system {
		req.SystemCache = nil
	}
	if !p.tools {
		for i := range req.Tools {
			req.Tools[i].Cache = nil
		}
	}
	if !p.messages {
		for i := range req.Messages {
			req.Messages[i].Cache = nil
		}
	}
	o := req.CacheOptions
	if o == nil {
		return
	}
	if !p.key {
		o.Key = ""
	}
	if !p.retention {
		o.Retention = ""
	}
	if !p.options {
		o.Mode, o.Options = "", nil
	}
	if !p.auto {
		o.Auto = nil
	}
	if o.empty() {
		req.CacheOptions = nil
	}
}

func cacheBreakpointsInOrder(req *CanonicalRequest) []*CanonicalCacheBreakpoint {
	var marks []*CanonicalCacheBreakpoint
	for i := range req.Tools {
		if req.Tools[i].Cache != nil {
			marks = append(marks, req.Tools[i].Cache)
		}
	}
	if req.SystemCache != nil {
		marks = append(marks, req.SystemCache)
	}
	for i := range req.Messages {
		if req.Messages[i].Cache != nil {
			marks = append(marks, req.Messages[i].Cache)
		}
	}
	if req.CacheOptions != nil && req.CacheOptions.Auto != nil {
		marks = append(marks, req.CacheOptions.Auto)
	}
	return marks
}

func dropEarliestCacheBreakpoint[T any](segments []T, cache func(*T) **CanonicalCacheBreakpoint) bool {
	first, count := -1, 0
	for i := range segments {
		if *cache(&segments[i]) != nil {
			if first < 0 {
				first = i
			}
			count++
		}
	}
	if count < 2 {
		return false
	}
	*cache(&segments[first]) = nil
	return true
}

// cacheTextJoin merges the text blocks of one segment with "\n" and keeps a
// single cache marker for it, remembering the block boundary it sat on as a
// newline index. Markers on block types the canonical model drops are
// dropped with the block.
type cacheTextJoin struct {
	parts    []string
	newlines int
	cache    *CanonicalCacheBreakpoint
}

func (j *cacheTextJoin) add(text string) {
	if len(j.parts) > 0 {
		j.newlines++
	}
	j.parts = append(j.parts, text)
	j.newlines += strings.Count(text, "\n")
}

func (j *cacheTextJoin) markText(bp *CanonicalCacheBreakpoint, last bool) {
	if bp != nil {
		bp.inText, bp.newline = true, j.newlines
		j.merge(bp, last)
	}
}

func (j *cacheTextJoin) markEnd(bp *CanonicalCacheBreakpoint, last bool) {
	if bp != nil {
		j.merge(bp, last)
	}
}

func (j *cacheTextJoin) merge(bp *CanonicalCacheBreakpoint, last bool) {
	j.cache = laterCacheBreakpoint(j.cache, bp)
	j.cache.clientLast = last && j.cache.TTL == bp.TTL
	j.cache.raisedLast = last && !j.cache.clientLast
	j.cache.clientTTL = bp.TTL
}

func (j *cacheTextJoin) breakpoint() *CanonicalCacheBreakpoint {
	if j.cache != nil && j.cache.inText {
		j.cache.newlines = j.newlines
	}
	return j.cache
}

// extend appends o's text as one more block of j and moves o's marker onto
// the same boundary in j. An empty o before any text adds nothing, so a
// leading empty block leaves no stray "\n".
func (j *cacheTextJoin) extend(o *cacheTextJoin) {
	text := o.String()
	if len(j.parts) == 0 && text == "" {
		return
	}
	base := 0
	if len(j.parts) > 0 {
		base = j.newlines + 1
	}
	j.add(text)
	bp := o.breakpoint()
	if bp == nil {
		return
	}
	shifted := *bp
	shifted.inText, shifted.newline = true, base+o.newlines
	if bp.inText {
		shifted.newline = base + bp.newline
	}
	j.merge(&shifted, false)
}

func (j *cacheTextJoin) String() string {
	return strings.Join(j.parts, "\n")
}

// cachedTextParts splits text back into the block the marker sat on and the
// text after it. placed reports that the marker belongs on parts[0]; when it
// is false the caller puts the marker on the last part it emits.
func cachedTextParts(text string, bp *CanonicalCacheBreakpoint) (parts []string, placed bool) {
	if text == "" {
		return nil, false
	}
	head, tail, ok := splitAtCacheBoundary(text, bp)
	if !ok {
		return []string{text}, false
	}
	if tail == "" {
		return []string{head}, true
	}
	return []string{head, tail}, true
}

// splitAtCacheBoundary finds the boundary by newline index rather than byte
// offset, so a plugin that changed the text's length without adding or
// removing lines (masking, anonymizing) still splits at the joiner. When the
// newline count changed, the index may point at a user newline, so it
// refuses; it also refuses a split that would leave a blank block, which
// Anthropic rejects.
func splitAtCacheBoundary(text string, bp *CanonicalCacheBreakpoint) (head, tail string, ok bool) {
	if bp == nil || !bp.inText || bp.newline > bp.newlines || strings.Count(text, "\n") != bp.newlines {
		return "", "", false
	}
	if bp.newline == bp.newlines {
		if strings.TrimSpace(text) == "" {
			return "", "", false
		}
		return text, "", true
	}
	at := 0
	for range bp.newline + 1 {
		at += strings.IndexByte(text[at:], '\n') + 1
	}
	head, tail = text[:at-1], text[at:]
	if strings.TrimSpace(head) == "" || strings.TrimSpace(tail) == "" {
		return "", "", false
	}
	return head, tail, true
}
