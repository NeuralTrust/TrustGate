package context

// ContextKey is the type used for request-scoped values stored in fiber Locals
// and the request context.Context. Stored under string(key) in Locals and under
// the typed key in context.Context, mirroring the metrics collector convention.
type ContextKey string

const (
	// SessionContextKey holds the session identifier resolved by the session
	// middleware from the per-gateway session configuration.
	SessionContextKey ContextKey = "session_id"
	// FingerprintIDContextKey holds the fingerprint identifier computed by the
	// fingerprint middleware.
	FingerprintIDContextKey ContextKey = "fingerprint_id"
	// TeamIDContextKey holds the team identifier decoded from an admin JWT.
	TeamIDContextKey ContextKey = "team_id"
	// UserIDContextKey holds the user identifier decoded from an admin JWT.
	UserIDContextKey ContextKey = "user_id"
	// UserEmailContextKey holds the user email decoded from an admin JWT.
	UserEmailContextKey ContextKey = "user_email"
)
