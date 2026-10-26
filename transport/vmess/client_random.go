package vmess

import (
	"crypto/aes"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/hkdf"
)

func deriveClientRandom(authKey []byte, sni string, salt []byte) ([]byte, error) {
	if len(authKey) == 0 || sni == "" {
		return nil, errors.New("missing TrustTunnel client random authentication data")
	}
	if salt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	} else if len(salt) != 16 {
		return nil, errors.New("invalid TrustTunnel client random salt")
	}
	key := make([]byte, 16)
	if _, err := io.ReadFull(hkdf.New(sha256.New, authKey, salt, []byte("tls13 encryption context")), key); err != nil {
		return nil, err
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256([]byte(sni))
	random := make([]byte, 32)
	copy(random, salt)
	cipher.Encrypt(random[16:], hash[:16])
	return random, nil
}
