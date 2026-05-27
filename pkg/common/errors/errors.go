package errors

import "errors"

var (
	ErrNotFound      = errors.New("resource not found")
	ErrInvalidConfig = errors.New("invalid configuration")
	ErrBoot          = errors.New("boot failure")
)
