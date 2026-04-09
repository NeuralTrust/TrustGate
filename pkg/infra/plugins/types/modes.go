package types

import "fmt"

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
)

func ValidateOption(option *Option) error {
	if option == nil || *option == "" {
		return nil
	}
	switch *option {
	case OptionEnforce, OptionObserve, OptionThrottle:
		return nil
	default:
		return fmt.Errorf("option must be one of: %s, %s, %s", OptionEnforce, OptionObserve, OptionThrottle)
	}
}
