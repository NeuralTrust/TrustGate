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

package registry_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	appopenapi "github.com/NeuralTrust/TrustGate/pkg/app/openapi"
	appregistry "github.com/NeuralTrust/TrustGate/pkg/app/registry"
	"github.com/NeuralTrust/TrustGate/pkg/domain/ids"
	domain "github.com/NeuralTrust/TrustGate/pkg/domain/registry"
	repomocks "github.com/NeuralTrust/TrustGate/pkg/domain/registry/mocks"
	infraopenapi "github.com/NeuralTrust/TrustGate/pkg/infra/openapi"
)

const genericFetchMessage = "openapi fetch: could not fetch the OpenAPI document"

func unreachableSpecURL(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("close listener: %v", err)
	}
	return "http://" + addr + "/openapi.json"
}

func TestOpenAPIValidator_FetchTransportFailureReturnsGenericMessage(t *testing.T) {
	t.Parallel()
	specURL := unreachableSpecURL(t)
	validator := appregistry.NewOpenAPIValidator(infraopenapi.NewCompilerWithClient(http.DefaultClient))

	result := validator.Validate(context.Background(), appopenapi.Source{SpecURL: specURL})

	if result.OK {
		t.Fatal("validation of an unreachable document succeeded")
	}
	if result.Stage != appopenapi.StageFetch {
		t.Fatalf("Stage = %q, want %q", result.Stage, appopenapi.StageFetch)
	}
	if result.Message != genericFetchMessage {
		t.Fatalf("Message = %q, want %q", result.Message, genericFetchMessage)
	}
	if strings.Contains(result.Message, "127.0.0.1") {
		t.Fatalf("Message exposes the dialled address: %q", result.Message)
	}
}

func TestOpenAPIValidator_KeepsDetailedNonTransportErrors(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/missing.json":
			http.NotFound(w, r)
		default:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"openapi":"3.0.3","info":{"title":"Broken"},"paths":{"/x":{"get":{"responses":"oops"}}}}`))
		}
	}))
	defer server.Close()
	validator := appregistry.NewOpenAPIValidator(infraopenapi.NewCompilerWithClient(server.Client()))

	parse := validator.Validate(context.Background(), appopenapi.Source{SpecURL: server.URL + "/openapi.json"})
	if parse.Stage != appopenapi.StageParse {
		t.Fatalf("Stage = %q, want %q (message %q)", parse.Stage, appopenapi.StageParse, parse.Message)
	}
	if !strings.HasPrefix(parse.Message, "openapi parse: ") || parse.Message == "openapi parse: " {
		t.Fatalf("parse message lost its detail: %q", parse.Message)
	}

	status := validator.Validate(context.Background(), appopenapi.Source{SpecURL: server.URL + "/missing.json"})
	if status.Stage != appopenapi.StageFetch {
		t.Fatalf("Stage = %q, want %q", status.Stage, appopenapi.StageFetch)
	}
	if !strings.Contains(status.Message, "404") {
		t.Fatalf("fetch message should keep the upstream status: %q", status.Message)
	}
}

func TestOpenAPIValidator_KeepsCompileStageMessage(t *testing.T) {
	t.Parallel()
	compiler := compilerFunc(func(context.Context, appopenapi.Source) (*appopenapi.Document, error) {
		return nil, &appopenapi.CompileError{Stage: appopenapi.StageCompile, Err: errors.New("the document has no callable operations")}
	})
	result := appregistry.NewOpenAPIValidator(compiler).Validate(context.Background(), appopenapi.Source{SpecURL: "https://api.example.com/openapi.json"})

	if result.Message != "openapi compile: the document has no callable operations" {
		t.Fatalf("Message = %q", result.Message)
	}
}

func TestCreator_Create_OpenAPIFetchTransportFailureIsGeneric(t *testing.T) {
	t.Parallel()
	specURL := unreachableSpecURL(t)
	repo := repomocks.NewRepository(t)
	creator := appregistry.NewCreator(repo, newCacheManager(), newTestLogger(), nil, nil,
		appregistry.WithOpenAPICompiler(infraopenapi.NewCompilerWithClient(http.DefaultClient)))

	_, err := creator.Create(context.Background(), appregistry.CreateInput{
		GatewayID: ids.New[ids.GatewayKind](),
		Name:      "example-api",
		Type:      domain.TypeMCP,
		MCPTarget: &domain.MCPTarget{
			Source:  domain.MCPSourceOpenAPI,
			OpenAPI: &domain.OpenAPITarget{SpecURL: specURL},
		},
	})

	if !errors.Is(err, domain.ErrInvalidMCPTarget) {
		t.Fatalf("error = %v, want ErrInvalidMCPTarget", err)
	}
	if !strings.HasSuffix(err.Error(), genericFetchMessage) {
		t.Fatalf("error = %q, want the generic fetch message", err.Error())
	}
	if strings.Contains(err.Error(), "127.0.0.1") {
		t.Fatalf("error exposes the dialled address: %q", err.Error())
	}
	var netErr net.Error
	if !errors.As(err, &netErr) {
		t.Fatal("the transport error should stay reachable through errors.As")
	}
}
