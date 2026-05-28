//go:build tools

// Package tools tracks Go-based developer tooling as project dependencies
// so their versions are pinned in go.mod / go.sum. The build tag keeps the
// imports out of regular builds.
//
// Install all tooling with:
//
//	go install github.com/vektra/mockery/v2
//
// Add new tools by importing their CLI package below.
package tools

import (
	_ "github.com/vektra/mockery/v2"
)
