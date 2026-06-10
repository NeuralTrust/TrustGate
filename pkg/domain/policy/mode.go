package policy

type Mode string

const (
	ModeEnforce  Mode = "enforce"
	ModeThrottle Mode = "throttle"
	ModeObserve  Mode = "observe"
)

const DefaultMode = ModeEnforce

func (m Mode) IsValid() bool {
	switch m {
	case ModeEnforce, ModeThrottle, ModeObserve:
		return true
	default:
		return false
	}
}

func (m Mode) Normalize() Mode {
	if m == "" {
		return DefaultMode
	}
	return m
}
