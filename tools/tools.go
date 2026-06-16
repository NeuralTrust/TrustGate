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
	_ "github.com/google/addlicense"
	_ "github.com/swaggo/swag/cmd/swag"
	_ "github.com/vektra/mockery/v2"
)
