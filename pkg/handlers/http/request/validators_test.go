package request

import (
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateWildcardPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		{name: "no wildcard", path: "/v1/users", wantErr: false},
		{name: "valid wildcard at end", path: "/v1/*", wantErr: false},
		{name: "multiple wildcards", path: "/v1/*/users/*", wantErr: true, errMsg: "only one wildcard"},
		{name: "wildcard not at end", path: "/v1/*/users", wantErr: true, errMsg: "only allowed at the end"},
		{name: "root wildcard", path: "/*", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateWildcardPath(tt.path)
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateHTTPMethods(t *testing.T) {
	tests := []struct {
		name    string
		methods []string
		wantErr bool
	}{
		{name: "empty is valid", methods: nil, wantErr: false},
		{name: "all valid methods", methods: []string{"GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}, wantErr: false},
		{name: "case insensitive valid", methods: []string{"get", "post"}, wantErr: false},
		{name: "invalid method", methods: []string{"GET", "INVALID"}, wantErr: true},
		{name: "single invalid", methods: []string{"TRACE"}, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateHTTPMethods(tt.methods)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateTrustLens(t *testing.T) {
	t.Run("missing team id", func(t *testing.T) {
		err := validateTrustLens(&types.TrustLensConfigDTO{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "team id is required")
	})

	t.Run("valid with team id only", func(t *testing.T) {
		err := validateTrustLens(&types.TrustLensConfigDTO{TeamID: "team-1"})
		assert.NoError(t, err)
	})

	t.Run("valid type", func(t *testing.T) {
		err := validateTrustLens(&types.TrustLensConfigDTO{TeamID: "team-1", Type: "MESSAGE"})
		assert.NoError(t, err)
	})

	t.Run("invalid type", func(t *testing.T) {
		err := validateTrustLens(&types.TrustLensConfigDTO{TeamID: "team-1", Type: "INVALID"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid trust lens type")
	})

	t.Run("valid data projection field", func(t *testing.T) {
		err := validateTrustLens(&types.TrustLensConfigDTO{
			TeamID: "team-1",
			Mapping: &types.TrustLensMappingDTO{
				Input:  types.TrustLensMappingDataDTO{DataProjection: map[string]string{"input": "$.message"}},
				Output: types.TrustLensMappingDataDTO{DataProjection: map[string]string{"output": "$.response"}},
			},
		})
		assert.NoError(t, err)
	})

	t.Run("invalid input data projection field", func(t *testing.T) {
		err := validateTrustLens(&types.TrustLensConfigDTO{
			TeamID: "team-1",
			Mapping: &types.TrustLensMappingDTO{
				Input: types.TrustLensMappingDataDTO{DataProjection: map[string]string{"invalid_field": "$.x"}},
			},
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid data_projection field in input")
	})
}

func TestValidateRuleType(t *testing.T) {
	tests := []struct {
		name     string
		ruleType string
		wantErr  bool
	}{
		{name: "agent valid", ruleType: "agent", wantErr: false},
		{name: "endpoint valid", ruleType: "endpoint", wantErr: false},
		{name: "invalid", ruleType: "webhook", wantErr: true},
		{name: "empty", ruleType: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateRuleType(tt.ruleType)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateRuleRequest_Validate(t *testing.T) {
	validReq := func() *CreateRuleRequest {
		return &CreateRuleRequest{
			Name:      "test-rule",
			Path:      types.FlexiblePath{Primary: "/api/v1"},
			ServiceID: "550e8400-e29b-41d4-a716-446655440000",
			Methods:   []string{"GET", "POST"},
		}
	}

	t.Run("valid minimal request", func(t *testing.T) {
		assert.NoError(t, validReq().Validate())
	})

	t.Run("missing name", func(t *testing.T) {
		r := validReq()
		r.Name = ""
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("missing path", func(t *testing.T) {
		r := validReq()
		r.Path = types.FlexiblePath{}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "path is required")
	})

	t.Run("empty path in multi-path", func(t *testing.T) {
		r := validReq()
		r.Path = types.FlexiblePath{Primary: "/v1", All: []string{"/v1", ""}}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "paths[1] must not be empty")
	})

	t.Run("missing methods", func(t *testing.T) {
		r := validReq()
		r.Methods = nil
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "at least one method is required")
	})

	t.Run("missing service_id", func(t *testing.T) {
		r := validReq()
		r.ServiceID = ""
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "service_id is required")
	})

	t.Run("invalid http method", func(t *testing.T) {
		r := validReq()
		r.Methods = []string{"GET", "INVALID"}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HTTP method")
	})

	t.Run("invalid rule type", func(t *testing.T) {
		r := validReq()
		invalid := "webhook"
		r.Type = &invalid
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid rule_type")
	})

	t.Run("valid rule type agent", func(t *testing.T) {
		r := validReq()
		agent := "agent"
		r.Type = &agent
		assert.NoError(t, r.Validate())
	})

	t.Run("wildcard path invalid", func(t *testing.T) {
		r := validReq()
		r.Path = types.FlexiblePath{Primary: "/v1/*/users"}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only allowed at the end")
	})
}

func TestUpdateRuleRequest_Validate(t *testing.T) {
	t.Run("empty request is valid", func(t *testing.T) {
		r := &UpdateRuleRequest{}
		assert.NoError(t, r.Validate())
	})

	t.Run("invalid method", func(t *testing.T) {
		r := &UpdateRuleRequest{Methods: []string{"INVALID"}}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid HTTP method")
	})

	t.Run("invalid type", func(t *testing.T) {
		invalid := "webhook"
		r := &UpdateRuleRequest{Type: &invalid}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid rule_type")
	})

	t.Run("invalid path wildcard", func(t *testing.T) {
		r := &UpdateRuleRequest{
			Path: &types.FlexiblePath{Primary: "/v1/*/users"},
		}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "only allowed at the end")
	})

	t.Run("valid path with wildcard", func(t *testing.T) {
		r := &UpdateRuleRequest{
			Path: &types.FlexiblePath{Primary: "/v1/*"},
		}
		assert.NoError(t, r.Validate())
	})

	t.Run("valid trustlens", func(t *testing.T) {
		r := &UpdateRuleRequest{
			TrustLens: &types.TrustLensConfigDTO{TeamID: "team-1"},
		}
		assert.NoError(t, r.Validate())
	})

	t.Run("invalid trustlens", func(t *testing.T) {
		r := &UpdateRuleRequest{
			TrustLens: &types.TrustLensConfigDTO{},
		}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "team id is required")
	})
}

func TestServiceRequest_Validate(t *testing.T) {
	t.Run("valid request", func(t *testing.T) {
		r := &ServiceRequest{Name: "svc", Type: "upstream"}
		assert.NoError(t, r.Validate())
	})

	t.Run("missing name", func(t *testing.T) {
		r := &ServiceRequest{Type: "upstream"}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "name is required")
	})

	t.Run("missing type", func(t *testing.T) {
		r := &ServiceRequest{Name: "svc"}
		err := r.Validate()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "type is required")
	})
}
