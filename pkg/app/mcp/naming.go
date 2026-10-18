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

// collisionSuffixLen is the hex appended when two servers genuinely expose one
// name. It stays off every other name: a client that stored those must not see
// them change because some other server happened to spell one tool the same way.
const collisionSuffixLen = 4

// resolveNames publishes the name tools/list and tools/call share. Two servers
// can spell different tools the same way — google's drive_list and
// google_drive's list are both google_drive_list — and then each takes a digest
// of the registry that serves it. A name nobody else serves is left as it was,
// so installing an unrelated server cannot rename it.
func resolveNames(candidates []binding, _ []*registrydomain.Registry) []binding {
	out := make([]binding, len(candidates))
	base := make([]string, len(candidates))
	count := make(map[string]int, len(candidates))
	for i, b := range candidates {
		name := exposedNameFor(b.exposed, b.registry).String()
		base[i] = name
		count[name]++
		out[i] = b
	}
	for i := range out {
		name := base[i]
		if count[name] > 1 {
			name = disambiguateCollision(name, out[i].registry)
		}
		out[i].exposed = name
	}
	return out
}

func disambiguateCollision(base string, reg *registrydomain.Registry) string {
	suffix := "_" + registryDigest(reg, collisionSuffixLen)
	if len(base)+len(suffix) <= maxExposedNameLength {
		return base + suffix
	}
	keep := maxExposedNameLength - len(suffix)
	if keep < 1 {
		return suffix[len(suffix)-maxExposedNameLength:]
	}
	return base[:keep] + suffix
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
	server := e.server
	suffix := contentSuffix(full)
	keep := maxExposedNameLength - len(server) - 1 - len(suffix)
	if keep < 1 && server != "" {
		// The slug crowds the tool out entirely. Cutting the slug instead
		// makes the prefix match miss, so every tool on that server answers
		// "Unknown tool". A short hash of the slug is still a prefix list and
		// call both know, and it leaves the tool room.
		server = hashedSlug(server)
		full = server + "_" + e.name
		if len(full) <= maxExposedNameLength {
			return full
		}
		suffix = contentSuffix(full)
		keep = maxExposedNameLength - len(server) - 1 - len(suffix)
	}
	if keep < 1 {
		return full[:maxExposedNameLength-len(suffix)] + suffix
	}
	return server + "_" + e.name[:keep] + suffix
}

func contentSuffix(full string) string {
	digest := sha256.Sum256([]byte(full))
	return "_" + hex.EncodeToString(digest[:nameHashLength/2])
}

// hashedSlug is the server prefix used when the slug itself is too long to
// leave a tool character. It is a property of the slug alone, so every tool on
// that server shares it and a call can find the server without being shown the
// list first.
func hashedSlug(slug string) string {
	digest := sha256.Sum256([]byte(slug))
	return hex.EncodeToString(digest[:nameHashLength/2])
}

// slugCrowdsOutTool reports that reserving the content-hash suffix would leave
// the tool with nothing, which is when String replaces the slug with hashedSlug.
func slugCrowdsOutTool(slug string) bool {
	return maxExposedNameLength-len(slug)-1-(1+nameHashLength) < 1
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
// each takes a short digest of its own registry id. That covers a Store
// principal's per-install clones that carry no config too: two configured
// instances of a server without URL variables, both installed, would otherwise
// serve every tool twice under one name. A registry wired by hand carries no
// code at all and takes the digest alone: opaque, but the price of having
// nothing stable to read.
func serverSlug(reg *registrydomain.Registry) string {
	if reg == nil {
		return ""
	}
	code := ""
	perInstance := !reg.InstanceOf.IsNil() && reg.ID != reg.InstanceOf
	if reg.MCPTarget != nil {
		code = strings.TrimSpace(reg.MCPTarget.Code)
		perInstance = perInstance || len(reg.MCPTarget.InstanceConfig) > 0
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

// registriesForExposedName returns every registry whose server prefix fits an
// exposed tool name. That name is "<server>_<tool>", so a tools/call does not
// dial a server that does not fit — dialing those minted a connect ticket for
// a server the call does not target.
//
// More than one prefix can fit. google_drive_list is google's drive_list and
// google_drive's list, and keeping only the longest used to make the shorter
// server's tool unreachable and answer with the longer server's consent. Every
// fit is returned; the caller keeps the one that serves the exact name.
func registriesForExposedName(registries []*registrydomain.Registry, name string) []*registrydomain.Registry {
	var owners []*registrydomain.Registry
	for _, reg := range registries {
		if matchedPrefixLen(reg, name) == 0 {
			continue
		}
		owners = append(owners, reg)
	}
	return owners
}

// matchedPrefixLen is the longest server prefix of reg that fits name, or 0
// when none does. A slug long enough to have been hashed also matches that hash.
func matchedPrefixLen(reg *registrydomain.Registry, name string) int {
	best := 0
	for _, prefix := range exposurePrefixes(serverSlug(reg)) {
		if strings.HasPrefix(name, prefix) && len(prefix) > best {
			best = len(prefix)
		}
	}
	return best
}

func exposurePrefixes(slug string) []string {
	if slug == "" {
		return nil
	}
	prefixes := []string{slug + "_"}
	if slugCrowdsOutTool(slug) {
		hashed := hashedSlug(slug) + "_"
		if hashed != prefixes[0] {
			prefixes = append(prefixes, hashed)
		}
	}
	return prefixes
}
