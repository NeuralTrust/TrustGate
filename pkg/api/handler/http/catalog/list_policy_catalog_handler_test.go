package catalog_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	cataloghttp "github.com/NeuralTrust/AgentGateway/pkg/api/handler/http/catalog"
	appplugins "github.com/NeuralTrust/AgentGateway/pkg/app/plugins"
	"github.com/NeuralTrust/AgentGateway/pkg/domain/policy"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeCatalogService struct {
	catalog appplugins.Catalog
}

func (f fakeCatalogService) Catalog() appplugins.Catalog { return f.catalog }

func TestListPolicyCatalogHandler_Handle(t *testing.T) {
	svc := fakeCatalogService{catalog: appplugins.Catalog{
		Groups: []appplugins.CatalogGroup{
			{
				Type: "Traffic Control",
				Items: []appplugins.CatalogEntry{
					{
						Slug:            "rate_limiter",
						Name:            "Rate Limiter",
						Description:     "Limit request volume.",
						MandatoryStages: []policy.Stage{policy.StagePreRequest},
						SupportedStages: []policy.Stage{policy.StagePreRequest},
						SettingsSchema: appplugins.SettingsSchema{
							Fields: []appplugins.Field{
								{Key: "limits", Label: "Limits", Type: appplugins.FieldTypeMap, Required: true},
							},
						},
					},
				},
			},
		},
	}}

	app := fiber.New()
	app.Get("/v1/policies-catalog", cataloghttp.NewListPolicyCatalogHandler(svc).Handle)

	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/v1/policies-catalog", nil))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var got appplugins.Catalog
	require.NoError(t, json.Unmarshal(body, &got))
	require.Len(t, got.Groups, 1)
	assert.Equal(t, "Traffic Control", got.Groups[0].Type)
	require.Len(t, got.Groups[0].Items, 1)
	assert.Equal(t, "rate_limiter", got.Groups[0].Items[0].Slug)
	assert.Equal(t, "Rate Limiter", got.Groups[0].Items[0].Name)
	require.Len(t, got.Groups[0].Items[0].SettingsSchema.Fields, 1)
	assert.Equal(t, "limits", got.Groups[0].Items[0].SettingsSchema.Fields[0].Key)
}
