package fingerprint

import (
	"encoding/base64"
	"errors"
	"strings"
)

type Fingerprint struct {
	UserID    string
	Token     string
	IP        string
	UserAgent string
}

func NewFromID(id string) (*Fingerprint, error) {
	decoded, err := base64.StdEncoding.DecodeString(id)
	if err != nil {
		return nil, err
	}
	parts := strings.Split(string(decoded), "|")
	if len(parts) != 4 {
		return nil, errors.New("invalid fingerprint ID format")
	}
	return &Fingerprint{
		UserID:    parts[0],
		Token:     parts[1],
		IP:        parts[2],
		UserAgent: parts[3],
	}, nil
}

func (f Fingerprint) ID() string {
	raw := f.UserID + "|" + f.Token + "|" + f.IP + "|" + f.UserAgent
	return base64.StdEncoding.EncodeToString([]byte(raw))
}
