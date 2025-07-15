package crypto

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

// CryptoOperations combines the contracts of KeyPair, Generator, and Marshaler.
// Any type that implements CryptoOperations must implement all methods
// defined in KeyPair, Generator, and Marshaler.
type CryptoOperations interface {
	KeyPair
	Generator
	Marshaler
}
