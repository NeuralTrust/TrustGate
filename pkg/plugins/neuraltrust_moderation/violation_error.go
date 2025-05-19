package neuraltrust_moderation

type moderationViolationError struct {
	message string
}

func (e *moderationViolationError) Error() string {
	return e.message
}

func NewModerationViolation(message string) error {
	return &moderationViolationError{message: message}
}
