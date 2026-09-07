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

package registry

import (
	"context"
	"errors"
	"fmt"

	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
)

type OpenAPIToolPreview struct {
	Name        string
	Description string
	Method      string
	Path        string
}

type OpenAPIValidationResult struct {
	OK             bool
	Stage          appopenapi.Stage
	OpenAPIVersion string
	Title          string
	BaseURL        string
	Tools          []OpenAPIToolPreview
	Warnings       []appopenapi.Warning
	Message        string
}

type OpenAPIValidator interface {
	Validate(ctx context.Context, source appopenapi.Source) OpenAPIValidationResult
}

type openAPIValidator struct {
	compiler appopenapi.Compiler
}

func NewOpenAPIValidator(compiler appopenapi.Compiler) OpenAPIValidator {
	return &openAPIValidator{compiler: compiler}
}

func (v *openAPIValidator) Validate(ctx context.Context, source appopenapi.Source) OpenAPIValidationResult {
	doc, err := v.compiler.Compile(ctx, source)
	if err != nil {
		stage := appopenapi.StageCompile
		var compileErr *appopenapi.CompileError
		if errors.As(err, &compileErr) {
			stage = compileErr.Stage
		}
		return OpenAPIValidationResult{Stage: stage, Message: err.Error()}
	}
	tools := make([]OpenAPIToolPreview, 0, len(doc.Operations))
	for _, operation := range doc.Operations {
		tools = append(tools, OpenAPIToolPreview{
			Name:        operation.Name,
			Description: operation.Description,
			Method:      operation.Method,
			Path:        operation.Path,
		})
	}
	return OpenAPIValidationResult{
		OK:             true,
		Stage:          appopenapi.StageCompile,
		OpenAPIVersion: doc.Version,
		Title:          doc.Title,
		BaseURL:        doc.BaseURL,
		Tools:          tools,
		Warnings:       doc.Warnings,
	}
}

func compileOpenAPITarget(ctx context.Context, target *domain.MCPTarget, compiler appopenapi.Compiler) error {
	if target == nil || target.Source != domain.MCPSourceOpenAPI {
		return nil
	}
	if compiler == nil {
		return fmt.Errorf("%w: openapi compiler is unavailable", domain.ErrInvalidMCPTarget)
	}
	if target.OpenAPI == nil {
		return fmt.Errorf("%w: openapi configuration is required", domain.ErrInvalidMCPTarget)
	}
	doc, err := compiler.Compile(ctx, appopenapi.Source{
		SpecURL: target.OpenAPI.SpecURL,
		BaseURL: target.URL,
	})
	if err != nil {
		return fmt.Errorf("%w: %w", domain.ErrInvalidMCPTarget, err)
	}
	target.URL = doc.BaseURL
	return nil
}
