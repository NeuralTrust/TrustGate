// Package mcpcatalog embeds the curated catalog of enterprise remote MCP servers
// so it ships inside the binary as the single source of truth for the
// MCP servers catalog endpoint.
package mcpcatalog

import "embed"

// EnterpriseServersJSON is the raw, curated catalog of remote MCP servers.
//
//go:embed enterprise-servers.json
var EnterpriseServersJSON []byte

// BrandsFS holds the MCP vendor logos used by the consent pages, keyed the
// same way as NeuralTrust/app `mcpBrands.ts`.
//
//go:embed brands
var BrandsFS embed.FS
