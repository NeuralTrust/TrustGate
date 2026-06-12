package errors

import "errors"

var (
	ErrNotFound      = errors.New("resource not found")
	ErrAlreadyExists = errors.New("resource already exists")
	ErrConflict      = errors.New("resource conflict")
	ErrHasDependents = errors.New("resource has dependents")
	ErrValidation    = errors.New("validation failed")
	ErrInvalidConfig = errors.New("invalid configuration")
	ErrBoot          = errors.New("boot failure")
)
