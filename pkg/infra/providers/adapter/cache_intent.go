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

	"github.com/NeuralTrust/TrustGate/pkg/domain/provider"
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
	// image is the 1-based position of the image block the marker sat on
	// among the segment's images, and images their count at decode time.
	// Encoders that emit images first keep the marker on that image; a
	// different count at encode time drops the marker instead of moving it
	// onto the text that followed the image.
	image, images int
	// text is the marker of an earlier text block of the segment, kept for
	// targets that send no images and so can still cache up to that block.
	text *CanonicalCacheBreakpoint
}

func (bp *CanonicalCacheBreakpoint) onImage() bool {
	return bp != nil && bp.image > 0
}

// withoutImages returns the marker a target that sends no images keeps: the
// text marker behind an image marker, or bp itself when it is not on an image.
func (bp *CanonicalCacheBreakpoint) withoutImages() *CanonicalCacheBreakpoint {
	if bp.onImage() {
		return bp.text
	}
	return bp
}

// cachedImageIndex returns the index of the image a marker sat on when the
// segment still has the images it was decoded with.
func cachedImageIndex(bp *CanonicalCacheBreakpoint, images int) (int, bool) {
	if !bp.onImage() || bp.images != images {
		return 0, false
	}
	return bp.image - 1, true
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

// openAICacheOptions keeps options verbatim and parses its mode. It returns
// nil when none of the three is set.
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
	// inputOnly reports that only user and tool messages can carry a
	// breakpoint, as Responses marks input parts and assistant items are
	// output.
	inputOnly bool
	// images reports that a breakpoint can stay on an image block.
	images                        bool
	max                           int
	key, retention, options, auto bool
	// implicitSlot reports that the provider spends one of the max writes on
	// its own breakpoint unless prompt_cache_options.mode is "explicit".
	implicitSlot bool
}

// cacheProfileFor returns what target accepts from providerName for model.
// Bedrock keeps images off until its encoder places cachePoint after the
// marked image (ENG-1618 S4a).
func cacheProfileFor(target Format, providerName, model string) cacheProfile {
	switch target {
	case FormatAnthropic:
		return cacheProfile{tools: true, system: true, messages: true, ttl1h: true, images: true, max: 4, auto: true}
	case FormatBedrock:
		return cacheProfile{tools: true, system: true, messages: true, ttl1h: true, max: 4}
	case FormatOpenAIResponses, FormatOpenAI, FormatAzure:
		return openAICacheProfile(target, providerName, model)
	default:
		return cacheProfile{}
	}
}

// openAICacheProfile gates the OpenAI cache keys on the provider, since
// Cerebras and openai_compatible share FormatOpenAI and reject or ignore
// them. GPT-5.6 and later take breakpoints and prompt_cache_options and no
// longer take prompt_cache_retention; earlier models answer 400 to the first
// two. An Azure model is usually a deployment name, so Azure gets only
// prompt_cache_key until a 400 fallback for retention exists (ENG-1618 S3).
func openAICacheProfile(target Format, providerName, model string) cacheProfile {
	switch providerName {
	case provider.OpenAI:
	case provider.Azure:
		return cacheProfile{key: true}
	default:
		return cacheProfile{}
	}
	explicit := isGPT56OrLater(model)
	p := cacheProfile{key: true, retention: !explicit, options: explicit}
	if target == FormatOpenAIResponses && explicit {
		p.system, p.messages, p.inputOnly, p.max, p.implicitSlot = true, true, true, 4, true
	}
	return p
}

// formatProvider names the provider a target format stands for when the
// caller does not know the actual one.
func formatProvider(target Format) string {
	if target == FormatOpenAIResponses {
		return provider.OpenAI
	}
	return string(target)
}

// isGPT56OrLater reports whether model is gpt-5.6, a later gpt-5 minor or a
// later major, with or without a vendor prefix ("openai/"), a fine-tune
// wrapper ("ft:gpt-5.6:org::id") or a suffix ("-2026-08-01", "-mini"). A
// two-digit major must end the name or be followed by "." or "-", and 35 is
// excluded because Azure spells GPT-3.5 "gpt-35-turbo".
func isGPT56OrLater(model string) bool {
	model = strings.ToLower(model)
	if i := strings.LastIndexByte(model, '/'); i >= 0 {
		model = model[i+1:]
	}
	model, _, _ = strings.Cut(strings.TrimPrefix(model, "ft:"), ":")
	rest, ok := strings.CutPrefix(model, "gpt-")
	if !ok {
		return false
	}
	major, after := leadingNumber(rest)
	switch digits := len(rest) - len(after); {
	case digits == 2:
		return major >= 10 && major != 35 && (after == "" || after[0] == '.' || after[0] == '-')
	case digits != 1 || major < 5:
		return false
	case major > 5:
		return true
	}
	minorText, ok := strings.CutPrefix(after, ".")
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

// normalizeCacheIntent applies the cache policy of target, served by
// providerName, to intent decoded from another format. defaultModel is the
// model the gateway sends when the request names none. Encoders stay
// faithful, so same-format re-encodes keep the client's markers exactly as
// sent. The cap runs before the TTL walk so a breakpoint that is dropped
// never downgrades the ones that stay.
func normalizeCacheIntent(req *CanonicalRequest, target Format, providerName, defaultModel string) {
	if req == nil {
		return
	}
	model := req.Model
	if model == "" {
		model = defaultModel
	}
	p := cacheProfileFor(target, providerName, model)
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
	if len(cacheBreakpointsInOrder(req)) == 0 {
		dropExplicitCacheMode(req)
	}
}

// dropExplicitCacheMode removes mode "explicit" from a request left without
// breakpoints: it turns off the provider's implicit breakpoint, so sent alone
// it would disable caching.
func dropExplicitCacheMode(req *CanonicalRequest) {
	o := req.CacheOptions
	if o == nil || o.Mode != "explicit" {
		return
	}
	o.Mode, o.Options = "", withoutCacheMode(o.Options)
	if o.empty() {
		req.CacheOptions = nil
	}
}

func withoutCacheMode(options json.RawMessage) json.RawMessage {
	var fields map[string]json.RawMessage
	if json.Unmarshal(options, &fields) != nil {
		return nil
	}
	delete(fields, "mode")
	if len(fields) == 0 {
		return nil
	}
	raw, err := json.Marshal(fields)
	if err != nil {
		return nil
	}
	return raw
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
	for i := range req.Messages {
		m := &req.Messages[i]
		if !p.images {
			m.Cache = m.Cache.withoutImages()
		}
		if !p.messages || (p.inputOnly && m.Role != "user" && m.Role != "tool") {
			m.Cache = nil
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
	images   int
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

func (j *cacheTextJoin) addImage() {
	j.images++
}

// markImage replaces any earlier marker rather than taking its TTL: images
// are emitted before the text, so the earlier marker's prefix no longer
// precedes the image. The earlier text marker stays behind the image marker
// for targets that send no images.
func (j *cacheTextJoin) markImage(bp *CanonicalCacheBreakpoint, last bool) {
	if bp == nil {
		return
	}
	var text *CanonicalCacheBreakpoint
	if prev := j.cache.withoutImages(); prev != nil && prev.inText {
		kept := *prev
		text = &kept
	}
	bp.image = j.images
	j.cache = nil
	j.merge(bp, last)
	j.cache.text = text
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
	if j.cache.onImage() {
		j.cache.images = j.images
		if j.cache.text != nil {
			j.cache.text.newlines = j.newlines
		}
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
// Anthropic rejects and OpenAI Chat and Responses gain nothing from.
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
