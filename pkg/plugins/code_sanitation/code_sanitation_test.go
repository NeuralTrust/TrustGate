package code_sanitation

import (
	"context"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/metrics"
	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCodeSanitationExecute_AllowsNullJSONValues(t *testing.T) {
	plugin := &CodeSanitationPlugin{
		logger: logrus.New(),
	}

	cfg := types.PluginConfig{
		Settings: map[string]interface{}{
			"content_to_check": []string{"body"},
			"action":           "sanitize",
			"sanitize_char":    "X",
			"languages": []map[string]interface{}{
				{
					"language": "shell",
					"enabled":  true,
				},
			},
		},
	}

	req := &types.RequestContext{
		Body: []byte(`{
			"messages": [
				{
					"id": "mhlyl5mq58tdnr9qbnf",
					"message": "rm -rf",
					"role": "user"
				}
			],
			"idSesion": null
		}`),
		Stage: types.PreRequest,
	}

	resp := &types.ResponseContext{}

	pluginResp, err := plugin.Execute(
		context.Background(),
		cfg,
		req,
		resp,
		metrics.NewEventContext("", "", nil),
	)

	require.NoError(t, err)
	require.NotNil(t, pluginResp)
	assert.JSONEq(t, `{
		"messages": [
			{
				"id": "mhlyl5mq58tdnr9qbnf",
				"message": "XXXXXX",
				"role": "user"
			}
		],
		"idSesion": null
	}`, string(req.Body))
}
