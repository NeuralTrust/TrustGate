package types

import (
	"fmt"
	"strings"
)

type Option string

const (
	OptionThrottle Option = "throttle"
	OptionEnforce  Option = "enforce"
	OptionObserve  Option = "observe"
)

type Decision string

const (
	DecisionBlock    Decision = "block"
	DecisionThrottle Decision = "throttle"
	DecisionMasked   Decision = "masked"
)

func ValidateOption(option *Option) error {
	return ValidateOptionAllowed(option, OptionEnforce, OptionObserve, OptionThrottle)
}

func ValidateOptionAllowed(option *Option, allowed ...Option) error {
	if option == nil || *option == "" {
		return nil
	}
	for _, a := range allowed {
		if *option == a {
			return nil
		}
	}
	names := make([]string, len(allowed))
	for i, a := range allowed {
		names[i] = string(a)
	}
	return fmt.Errorf("option must be one of: %s", strings.Join(names, ", "))
}
