package neuraltrust_jailbreak

type guardrailViolationError struct {
	message string
}

func (e *guardrailViolationError) Error() string {
	return e.message
}

func NewGuardrailViolation(message string) error {
	return &guardrailViolationError{message: message}
}
