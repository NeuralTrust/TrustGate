package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/url"
	"strings"
)

func clientRedirect(redirectURI string, params url.Values, state string) string {
	if state != "" {
		params.Set("state", state)
	}
	sep := "?"
	if strings.Contains(redirectURI, "?") {
		sep = "&"
	}
	return redirectURI + sep + params.Encode()
}

func mergeScopes(requested string, required []string) string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range append(strings.Fields(requested), required...) {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return strings.Join(out, " ")
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", errors.New("oauth: entropy unavailable")
	}
	return hex.EncodeToString(buf), nil
}
