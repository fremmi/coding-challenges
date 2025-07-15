package crypto

import "errors"

var ErrUnsupportedAlgorithm = errors.New("unsupported algorithm")

type Algorithm string

const (
	AlgorithmRSA Algorithm = "RSA"
	AlgorithmECC Algorithm = "ECC"
)

// KeyPair defines a contract for key pair implementations.
type KeyPair interface {
	GetPrivate() any
	GetPublic() any
}

// Generator defines a contract for key pair generation implementations.
type Generator interface {
	GenerateKeyPair() (KeyPair, error)
}

// Marshaler defines a contract for key pair encoding and decoding implementations.
type Marshaler interface {
	Encode(keyPair KeyPair) ([]byte, []byte, error)
	Decode(privateKeyBytes []byte) (KeyPair, error)
}
