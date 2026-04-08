package fingerprint

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	maxTokenLen     = 128
	maxUserAgentLen = 256
	maxIDLen        = 512
)

type Fingerprint struct {
	UserID    string
	Token     string
	IP        string
	UserAgent string
	SessionID string
}

func NewFromID(id string) (*Fingerprint, error) {
	decoded, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(decoded), "|")
	if len(parts) < 4 {
		return nil, errors.New("invalid fingerprint ID format")
	}
	fp := &Fingerprint{
		UserID:    parts[0],
		Token:     parts[1],
		IP:        parts[2],
		UserAgent: parts[3],
	}
	if len(parts) >= 5 {
		fp.SessionID = parts[4]
	}
	return fp, nil
}

func (f Fingerprint) ID() string {
	raw := f.UserID + "|" + f.Token + "|" + f.IP + "|" + f.UserAgent + "|" + f.SessionID
	return base64.StdEncoding.EncodeToString([]byte(raw))
}

func hashField(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func compactField(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return hashField(s)
}

func CompactID(id string) string {
	if len(id) <= maxIDLen {
		return id
	}
	fp, err := NewFromID(id)
	if err != nil {
		return hashField(id)
	}
	fp.Token = compactField(fp.Token, maxTokenLen)
	fp.UserAgent = compactField(fp.UserAgent, maxUserAgentLen)
	return fp.ID()
}
