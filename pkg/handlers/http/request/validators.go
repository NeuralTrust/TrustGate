package request

import (
	"fmt"
	"strings"

	"github.com/NeuralTrust/TrustGate/pkg/types"
)

func validateWildcardPath(path string) error {
	if !strings.Contains(path, "*") {
		return nil
	}
	if strings.Count(path, "*") > 1 {
		return fmt.Errorf("only one wildcard (*) is allowed per path")
	}
	if !strings.HasSuffix(path, "/*") {
		return fmt.Errorf("wildcard (*) is only allowed at the end of a path (e.g. /v1/*)")
	}
	return nil
}

func validateHTTPMethods(methods []string) error {
	if len(methods) == 0 {
		return nil
	}

	validMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"PATCH":   true,
		"HEAD":    true,
		"OPTIONS": true,
	}

	for _, method := range methods {
		if !validMethods[strings.ToUpper(method)] {
			return fmt.Errorf("invalid HTTP method: %s", method)
		}
	}
	return nil
}

func validateTrustLens(trustLens *types.TrustLensConfigDTO) error {
	if trustLens.TeamID == "" {
		return fmt.Errorf("trust lens team id is required")
	}

	if trustLens.Type != "" {
		validTypes := map[string]bool{
			"MESSAGE":    true,
			"TOOL":       true,
			"AGENT":      true,
			"RETRIEVAL":  true,
			"GENERATION": true,
			"ROUTER":     true,
			"SYSTEM":     true,
			"FEEDBACK":   true,
		}
		if !validTypes[strings.ToUpper(trustLens.Type)] {
			return fmt.Errorf("invalid trust lens type: %s. Must be one of: MESSAGE, TOOL, AGENT, RETRIEVAL, GENERATION, ROUTER, SYSTEM, FEEDBACK", trustLens.Type)
		}
	}

	if trustLens.Mapping != nil {
		validDataProjectionFields := map[string]bool{
			"input":         true,
			"output":        true,
			"feedback_tag":  true,
			"feedback_text": true,
		}

		for key := range trustLens.Mapping.Input.DataProjection {
			if !validDataProjectionFields[key] {
				return fmt.Errorf("invalid data_projection field in input: %s. Must be one of: input, output, feedback_tag, feedback_text", key)
			}
		}

		for key := range trustLens.Mapping.Output.DataProjection {
			if !validDataProjectionFields[key] {
				return fmt.Errorf("invalid data_projection field in output: %s. Must be one of: input, output, feedback_tag, feedback_text", key)
			}
		}
	}

	return nil
}

func validateRuleType(ruleType string) error {
	if ruleType != "agent" && ruleType != "endpoint" {
		return fmt.Errorf("invalid rule_type, must be 'agent' or 'endpoint'")
	}
	return nil
}
