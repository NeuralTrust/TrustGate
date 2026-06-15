package vault

//go:generate mockery --name=Encrypter --dir=. --output=./mocks --filename=vault_encrypter_mock.go --case=underscore --with-expecter
type Encrypter interface {
	Encrypt(plaintext string) (string, error)
	Decrypt(ciphertext string) (string, error)
}
