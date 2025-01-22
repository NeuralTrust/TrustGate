package utils

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

func GenerateApiKey() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return fmt.Sprintf("key-%s", base64.URLEncoding.EncodeToString(bytes))
}
