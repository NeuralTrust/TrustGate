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

package requestmeta

import "strings"

const (
	// HeaderTraceparent is the W3C Trace Context header a client sends to tie
	// its own spans to the request.
	HeaderTraceparent = "traceparent"
	// HeaderMCPSessionID is the session header of the MCP Streamable HTTP
	// transport.
	HeaderMCPSessionID = "Mcp-Session-Id"
)

const (
	traceparentLen     = 55
	traceIDStart       = 3
	traceIDEnd         = 35
	maxMCPSessionIDLen = 256
)

// ClientTraceID returns the trace-id field of the client's traceparent, as
// received, or "" when the header is absent, repeated or not a valid W3C
// traceparent. It never makes one up: an empty result means the client sent
// nothing the gateway can join requests on.
func ClientTraceID(values []string) string {
	if len(values) != 1 {
		return ""
	}
	v := values[0]
	if !validTraceparent(v) {
		return ""
	}
	return strings.Clone(v[traceIDStart:traceIDEnd])
}

// validTraceparent applies the W3C Trace Context parsing rules: a version other
// than ff, lowercase hex fields, non-zero trace-id and parent-id, and a length
// of exactly 55 for version 00. A higher version may append fields after a
// dash, which a version-00 parser must accept and ignore.
func validTraceparent(v string) bool {
	if len(v) < traceparentLen {
		return false
	}
	version, traceID, parentID, flags := v[0:2], v[3:35], v[36:52], v[53:55]
	if v[2] != '-' || v[35] != '-' || v[52] != '-' {
		return false
	}
	if !lowerHex(version) || version == "ff" {
		return false
	}
	if version == "00" && len(v) != traceparentLen {
		return false
	}
	if len(v) > traceparentLen && v[traceparentLen] != '-' {
		return false
	}
	return lowerHex(traceID) && !allZero(traceID) &&
		lowerHex(parentID) && !allZero(parentID) &&
		lowerHex(flags)
}

// MCPSessionID returns the Mcp-Session-Id the client sent, or "" when it is
// absent, repeated, longer than 256 bytes, or holds anything but visible ASCII,
// which is all the MCP transport allows in a session id.
func MCPSessionID(values []string) string {
	if len(values) != 1 {
		return ""
	}
	v := values[0]
	if v == "" || len(v) > maxMCPSessionIDLen {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return ""
		}
	}
	return strings.Clone(v)
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func allZero(s string) bool {
	return strings.Trim(s, "0") == ""
}
