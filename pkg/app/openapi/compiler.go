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

package openapi

import (
	"context"
	"encoding/json"
)

type Source struct {
	SpecURL string
	BaseURL string
}

type Parameter struct {
	Name     string
	In       string
	Required bool
	Style    string
	Explode  bool
}

type Operation struct {
	Name         string
	Description  string
	Method       string
	Path         string
	InputSchema  json.RawMessage
	Parameters   []Parameter
	BodyFields   []string
	BodyArgument string
}

type Warning struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type Document struct {
	Version    string
	Title      string
	BaseURL    string
	Operations []Operation
	Warnings   []Warning
}

type Compiler interface {
	Compile(ctx context.Context, source Source) (*Document, error)
}
