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

import "encoding/json"

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
// The unexported fields are set by the Anthropic decoder, which joins a
// segment's text blocks with "\n". They let the Anthropic encoder split the
// text back at the marked block even after a plugin changed its length.
// Encoders for other targets ignore them.
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

type cacheProfile struct {
	tools, system, messages, ttl1h bool
	max                            int
	key, retention, options, auto  bool
}

func cacheProfileFor(target Format) cacheProfile {
	switch target {
	case FormatAnthropic:
		return cacheProfile{tools: true, system: true, messages: true, ttl1h: true, max: 4, auto: true}
	case FormatBedrock:
		return cacheProfile{tools: true, system: true, messages: true, ttl1h: true, max: 4}
	default:
		return cacheProfile{}
	}
}

// laterCacheBreakpoint merges two markers of one segment into a new one: the
// later position with the longer TTL. Raising the later marker to 1h stays
// valid because every marker before a 1h one must already be 1h.
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
	p := cacheProfileFor(target)
	dropDisallowedCacheIntent(req, p)

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

// dropEarliestCacheBreakpoint clears the first breakpoint in segments unless it
// is the only one left, so every section keeps its last boundary.
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
