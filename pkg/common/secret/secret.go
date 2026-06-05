package secret

// Redacted is the placeholder the API returns instead of a stored secret. It is
// never persisted: on writes it is treated as "no change" so a read-modify-write
// round-trip cannot overwrite a real credential with the mask.
const Redacted = "***"

// Resolve implements the merge-on-omit rule for secret fields on update: when the
// incoming value is empty or the redaction placeholder, the existing stored value
// is kept; otherwise the incoming value replaces it.
func Resolve(incoming, existing string) string {
	if incoming == "" || incoming == Redacted {
		return existing
	}
	return incoming
}

// Mask returns the redaction placeholder when a secret is set, and empty otherwise,
// so responses signal that a credential exists without exposing it.
func Mask(v string) string {
	if v == "" {
		return ""
	}
	return Redacted
}

// IsRedacted reports whether a value is the redaction placeholder. It is used to
// reject the sentinel as a literal secret on writes where there is no stored
// value to keep (create, auth type switch, first-time config).
func IsRedacted(v string) bool {
	return v == Redacted
}
