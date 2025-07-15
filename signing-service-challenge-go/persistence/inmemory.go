package persistence

import (
	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
)

type PersistedDevice struct {
	ID         string           `json:"id"`
	Label      string           `json:"label"`
	Algorithm  crypto.Algorithm `json:"algorithm"` // "RSA" or "ECC" so far
	Counter    int64            `json:"counter"`
	PrivatePEM []byte           `json:"private_key"` // PEM-encoded private key
	PublicPem  []byte           `json:"public_key"`  // PEM-encoded public key
}
