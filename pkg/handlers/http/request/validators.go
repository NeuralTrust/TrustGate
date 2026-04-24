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

	return nil
}

func validateRuleType(ruleType string) error {
	if ruleType != "agent" && ruleType != "endpoint" {
		return fmt.Errorf("invalid rule_type, must be 'agent' or 'endpoint'")
	}
	return nil
}
