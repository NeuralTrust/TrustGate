package oauth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"slices"
	"strings"
)

type oauthTokenCacheFingerprints struct {
	TokenURL     string            `json:"token_url"`
	GrantType    string            `json:"grant_type"`
	ClientID     string            `json:"client_id,omitempty"`
	ClientSecret string            `json:"client_secret,omitempty"` // #nosec G117 -- hashed via SHA256; used only for cache key material
	UseBasicAuth bool              `json:"use_basic_auth,omitempty"`
	Scopes       []string          `json:"scopes,omitempty"`
	Audience     string            `json:"audience,omitempty"`
	Extra        map[string]string `json:"extra,omitempty"`
	RefreshToken string            `json:"refresh_token,omitempty"` // #nosec G117 -- fingerprint only; not stored in Redis under this struct
	Code         string            `json:"code,omitempty"`
	RedirectURI  string            `json:"redirect_uri,omitempty"`
	CodeVerifier string            `json:"code_verifier,omitempty"`
	Username     string            `json:"username,omitempty"`
	Password     string            `json:"password,omitempty"` // #nosec G117 -- fingerprint only for non-cached grants
}

func oauthTokenCacheKeyFingerprint(dto TokenRequestDTO) string {
	scopes := append([]string(nil), dto.Scopes...)
	slices.Sort(scopes)

	extra := dto.Extra
	if extra == nil {
		extra = map[string]string{}
	}

	wire := oauthTokenCacheFingerprints{
		TokenURL:     normalizeTokenURLForCache(dto.TokenURL),
		GrantType:    string(dto.GrantType),
		ClientID:     dto.ClientID,
		ClientSecret: dto.ClientSecret,
		UseBasicAuth: dto.UseBasicAuth,
		Scopes:       scopes,
		Audience:     dto.Audience,
		Extra:        extra,
		RefreshToken: dto.RefreshToken,
		Code:         dto.Code,
		RedirectURI:  dto.RedirectURI,
		CodeVerifier: dto.CodeVerifier,
		Username:     dto.Username,
		Password:     dto.Password,
	}

	b, err := json.Marshal(wire) // #nosec G117 -- JSON for SHA256 fingerprint only, never persisted or logged
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func normalizeTokenURLForCache(raw string) string {
	return strings.TrimSpace(strings.TrimPrefix(raw, "@"))
}
