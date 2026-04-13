package gcp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/NeuralTrust/TrustGate/pkg/infra/crypto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestCrypto(t *testing.T) crypto.EncryptionService {
	t.Helper()
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	svc, err := crypto.NewEncryptionService(hex.EncodeToString(key))
	require.NoError(t, err)
	return svc
}

func validSAJSON() map[string]string {
	return map[string]string{
		"type":                        "service_account",
		"project_id":                  "my-project",
		"private_key_id":              "abc123",
		"private_key":                 "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n", // #nosec G101 -- test fixture
		"client_email":                "test@my-project.iam.gserviceaccount.com",
		"client_id":                   "123456789",
		"auth_uri":                    "https://accounts.google.com/o/oauth2/auth",
		"token_uri":                   "https://oauth2.googleapis.com/token",
		"auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
		"client_x509_cert_url":        "https://www.googleapis.com/robot/v1/metadata/x509/test",
		"universe_domain":             "googleapis.com",
	}
}

func validSABase64(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(validSAJSON())
	require.NoError(t, err)
	return base64.StdEncoding.EncodeToString(data)
}

func TestValidateSA(t *testing.T) {
	svc := NewServiceAccountService(newTestCrypto(t))

	t.Run("valid service account", func(t *testing.T) {
		err := svc.ValidateSA(validSABase64(t))
		assert.NoError(t, err)
	})

	t.Run("invalid base64", func(t *testing.T) {
		err := svc.ValidateSA("not-base64!!!")
		assert.ErrorContains(t, err, "invalid base64")
	})

	t.Run("invalid JSON", func(t *testing.T) {
		err := svc.ValidateSA(base64.StdEncoding.EncodeToString([]byte("not json")))
		assert.ErrorContains(t, err, "invalid JSON")
	})

	t.Run("wrong type", func(t *testing.T) {
		sa := validSAJSON()
		sa["type"] = "wrong"
		data, _ := json.Marshal(sa)
		err := svc.ValidateSA(base64.StdEncoding.EncodeToString(data))
		assert.ErrorContains(t, err, "must be 'service_account'")
	})

	t.Run("missing private_key", func(t *testing.T) {
		sa := validSAJSON()
		delete(sa, "private_key")
		data, _ := json.Marshal(sa)
		err := svc.ValidateSA(base64.StdEncoding.EncodeToString(data))
		assert.ErrorContains(t, err, "private_key")
	})

	t.Run("missing client_email", func(t *testing.T) {
		sa := validSAJSON()
		delete(sa, "client_email")
		data, _ := json.Marshal(sa)
		err := svc.ValidateSA(base64.StdEncoding.EncodeToString(data))
		assert.ErrorContains(t, err, "client_email")
	})

	t.Run("missing token_uri", func(t *testing.T) {
		sa := validSAJSON()
		delete(sa, "token_uri")
		data, _ := json.Marshal(sa)
		err := svc.ValidateSA(base64.StdEncoding.EncodeToString(data))
		assert.ErrorContains(t, err, "token_uri")
	})
}

func TestEncryptDecryptSA(t *testing.T) {
	cryptoSvc := newTestCrypto(t)
	svc := NewServiceAccountService(cryptoSvc)

	b64 := validSABase64(t)

	encrypted, err := svc.EncryptSA(b64)
	require.NoError(t, err)
	assert.NotEqual(t, b64, encrypted)

	result, err := svc.DecryptSA("upstream-1", "target-1", encrypted)
	require.NoError(t, err)

	expected := validSAJSON()
	assert.Equal(t, expected["client_email"], result["client_email"])
	assert.Equal(t, expected["project_id"], result["project_id"])
	assert.Equal(t, expected["token_uri"], result["token_uri"])
}

func TestDecryptSACacheHit(t *testing.T) {
	cryptoSvc := newTestCrypto(t)
	svc := NewServiceAccountService(cryptoSvc)

	b64 := validSABase64(t)
	encrypted, err := svc.EncryptSA(b64)
	require.NoError(t, err)

	result1, err := svc.DecryptSA("u1", "t1", encrypted)
	require.NoError(t, err)

	result2, err := svc.DecryptSA("u1", "t1", encrypted)
	require.NoError(t, err)

	assert.Equal(t, result1, result2)
}

func TestDecryptSADifferentKeys(t *testing.T) {
	cryptoSvc := newTestCrypto(t)
	svc := NewServiceAccountService(cryptoSvc)

	b64 := validSABase64(t)
	encrypted, err := svc.EncryptSA(b64)
	require.NoError(t, err)

	r1, err := svc.DecryptSA("u1", "t1", encrypted)
	require.NoError(t, err)

	r2, err := svc.DecryptSA("u1", "t2", encrypted)
	require.NoError(t, err)

	assert.Equal(t, r1, r2)
}
