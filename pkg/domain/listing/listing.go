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

// Package listing holds shared pagination and sort value objects for list queries.
package listing

const (
	DefaultPage = 1
	DefaultSize = 20
)

// Direction is the sort direction for a list query.
type Direction string

const (
	Asc  Direction = "asc"
	Desc Direction = "desc"
)

// SQL returns the SQL keyword for this direction. Empty defaults to DESC.
func (d Direction) SQL() string {
	if d == Asc {
		return "ASC"
	}
	return "DESC"
}

// Page is a 1-based page request.
type Page struct {
	Number int
	Size   int
}

// Normalize applies defaults for missing page/size values.
func (p Page) Normalize() Page {
	if p.Number < 1 {
		p.Number = DefaultPage
	}
	if p.Size < 1 {
		p.Size = DefaultSize
	}
	return p
}

// Offset returns the SQL OFFSET for this page.
func (p Page) Offset() int {
	n := p.Normalize()
	return (n.Number - 1) * n.Size
}

// Sort is an optional field + direction pair. A zero Sort means the repository
// default (typically created_at DESC). Field must be validated against a
// whitelist before it reaches SQL.
type Sort struct {
	Field     string
	Direction Direction
}

// IsZero reports whether no sort was requested.
func (s Sort) IsZero() bool {
	return s.Field == ""
}
