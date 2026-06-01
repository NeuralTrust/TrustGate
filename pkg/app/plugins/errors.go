package plugins

import "errors"

// PluginError is returned by a plugin to reject a request and short-circuit the
// chain with a specific HTTP status (e.g. rate limit 429, CORS preflight 204).
type PluginError struct {
	StatusCode int
	Message    string
	Headers    map[string][]string
}

func (e *PluginError) Error() string {
	return e.Message
}

// AsPluginError reports whether err is (or wraps) a *PluginError and returns it.
func AsPluginError(err error) (*PluginError, bool) {
	var pe *PluginError
	if errors.As(err, &pe) {
		return pe, true
	}
	return nil, false
}
