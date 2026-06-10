package idp

import "errors"

var (
	ErrInvalidToken         = errors.New("invalid idp token")
	ErrJWKSFetch            = errors.New("jwks fetch failed")
	ErrUnsupportedKey       = errors.New("unsupported idp key")
	ErrUnsupportedAlg       = errors.New("unsupported idp signing algorithm")
	ErrMissingKey           = errors.New("missing idp signing key")
	ErrMissingRequiredScope = errors.New("missing required idp scope")
)
