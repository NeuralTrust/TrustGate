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

package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	registrydomain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

// maxExposedNameLength is what an MCP client will accept for a tool name.
const maxExposedNameLength = 64

// nameHashLength is the hex a truncated name ends in, enough that two tools
// truncated to the same stem stay apart.
const nameHashLength = 8

func resolveNames(candidates []binding, _ []*registrydomain.Registry) []binding {
	out := make([]binding, 0, len(candidates))
	for _, b := range candidates {
		b.exposed = exposedNameFor(b.exposed, b.registry).String()
		out = append(out, b)
	}
	return out
}

// exposedName is a tool as the caller sees it: the server it came from, and
// the name that server gave it.
type exposedName struct {
	name   string
	server string
}

func exposedNameFor(name string, reg *registrydomain.Registry) exposedName {
	return exposedName{name: name, server: serverSlug(reg)}
}

// String is the name the caller calls the tool by: <server>_<tool>.
//
// Every tool carries its server, always — with one server bound or twenty.
// The prefix used to appear only once a second server showed up, which made a
// tool's name depend on what else the caller happened to have: installing
// anything renamed every tool they already had, and a conversation holding the
// old names was left calling tools that no longer existed. Qualifying only on a
// real collision moves the dependency rather than removing it — a name would
// then change when the colliding server went unreachable. A name has to depend
// on the tool and nothing else, and the only way there is to spell it out every
// time.
//
// It also says something a bare "search" does not: which of the caller's
// servers is about to be searched.
func (e exposedName) String() string {
	full := e.server + "_" + e.name
	if e.server == "" {
		full = e.name
	}
	if len(full) <= maxExposedNameLength {
		return full
	}
	// Too long for the client to accept. The server stays whole — it is what
	// tells two same-named tools apart — and the tool's name gives up its tail
	// to a digest of the whole thing, which depends on nothing else either.
	digest := sha256.Sum256([]byte(full))
	suffix := "_" + hex.EncodeToString(digest[:nameHashLength/2])
	keep := maxExposedNameLength - len(e.server) - 1 - len(suffix)
	if keep < 1 {
		// A server name long enough to crowd out the tool entirely: hash the lot.
		return full[:maxExposedNameLength-len(suffix)] + suffix
	}
	return e.server + "_" + e.name[:keep] + suffix
}

// serverSlug names the server a tool came from, in a way that survives
// everything but the server being replaced.
//
// The catalog code is the one stable, unique identifier a server has: an
// admin's rename does not touch it, and no two catalog entries share one. The
// leading reverse-DNS label and a trailing "/mcp" carry no information and only
// cost the reader, so com.notion/mcp reads as "notion" and
// com.google_cloud/developerknowledge as "google_cloud_developerknowledge".
//
// Several instances of one code — a Snowflake schema per team — share it, so
// each takes a short digest of its own registry id. A registry wired by hand
// carries no code at all and takes the digest alone: opaque, but the price of
// having nothing stable to read.
func serverSlug(reg *registrydomain.Registry) string {
	if reg == nil {
		return ""
	}
	code := ""
	perInstance := false
	if reg.MCPTarget != nil {
		code = strings.TrimSpace(reg.MCPTarget.Code)
		perInstance = len(reg.MCPTarget.InstanceConfig) > 0
	}
	slug := slugFromCatalogCode(code)
	if slug == "" {
		return "s" + registryDigest(reg, 8)
	}
	if perInstance {
		return slug + "_" + registryDigest(reg, 6)
	}
	return slug
}

func registryDigest(reg *registrydomain.Registry, n int) string {
	sum := sha256.Sum256([]byte(reg.ID.String()))
	return hex.EncodeToString(sum[:])[:n]
}

// slugFromCatalogCode turns a catalog code into the readable part of a tool
// name. Empty for a code that leaves nothing behind.
func slugFromCatalogCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if code == "" {
		return ""
	}
	code = strings.TrimSuffix(code, "/mcp")
	// The reverse-DNS label ("com.", "io.", "ai.") is the same for hundreds of
	// entries; what follows it is the name. Everything after the first label is
	// kept, because com.google_cloud/logging and com.google_cloud/monitoring are
	// different servers.
	if head, rest, found := strings.Cut(code, "."); found && head != "" && rest != "" {
		code = rest
	}
	var b strings.Builder
	lastUnderscore := false
	for _, r := range code {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			lastUnderscore = false
		case !lastUnderscore && b.Len() > 0:
			b.WriteByte('_')
			lastUnderscore = true
		}
	}
	return strings.Trim(b.String(), "_")
}
