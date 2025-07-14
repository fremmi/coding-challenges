package crypto

type KeyPair interface {
	GetPrivate() any
	GetPublic() any
}

type Generator interface {
	GenerateKeyPair() (KeyPair, error)
}

type Marshaler interface {
	Encode(keyPair KeyPair) ([]byte, []byte, error)
	Decode(privateKeyBytes []byte) (KeyPair, error)
}
