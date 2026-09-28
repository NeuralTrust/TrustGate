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

package modules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/stretchr/testify/require"
)

// AdminRouterDeps is filled by hand rather than by dig, so declaring a handler
// field and providing its constructor is not enough: the field also has to be
// assigned in the composite literal below. Miss that and the field stays nil, the
// route registers anyway, and every call to it panics into a 500 — which is how
// the prompt-template preview endpoint shipped dead (RUN-1640).
func TestEveryAdminRouterDepIsWired(t *testing.T) {
	t.Parallel()

	declared := structFields(t, "../../server/router/admin_router.go", "AdminRouterDeps")
	require.NotEmpty(t, declared, "AdminRouterDeps fields not found")

	assigned := literalKeys(t, "server_admin.go", "AdminRouterDeps")
	require.NotEmpty(t, assigned, "AdminRouterDeps literal not found")

	for _, field := range declared {
		require.Contains(t, assigned, field,
			"AdminRouterDeps.%s is declared and routed but never assigned in server_admin.go, so it stays nil and its route panics", field)
	}
}

func structFields(t *testing.T, path, name string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)

	var fields []string
	ast.Inspect(file, func(n ast.Node) bool {
		spec, ok := n.(*ast.TypeSpec)
		if !ok || spec.Name.Name != name {
			return true
		}
		st, ok := spec.Type.(*ast.StructType)
		if !ok {
			return false
		}
		for _, f := range st.Fields.List {
			for _, ident := range f.Names {
				fields = append(fields, ident.Name)
			}
		}
		return false
	})
	return fields
}

func literalKeys(t *testing.T, path, name string) map[string]struct{} {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)

	keys := map[string]struct{}{}
	ast.Inspect(file, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok {
			return true
		}
		sel, ok := lit.Type.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != name {
			return true
		}
		for _, elt := range lit.Elts {
			kv, ok := elt.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			if ident, ok := kv.Key.(*ast.Ident); ok {
				keys[ident.Name] = struct{}{}
			}
		}
		return false
	})
	return keys
}
