package vault

// Encrypter is the at-rest encryption contract for vaulted secrets: tokens
// MUST be sealed before persistence and opened on read. Implemented in infra
// (AES-GCM today; KMS-backed implementations satisfy the same port).
//
//go:generate mockery --name=Encrypter --dir=. --output=./mocks --filename=vault_encrypter_mock.go --case=underscore --with-expecter
type Encrypter interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}
