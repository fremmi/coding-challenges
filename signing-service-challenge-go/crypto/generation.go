package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// Builder functions. Useful for testing or when you want to use a different implementation.
var NewRsaGenerator = func() Generator {
	return &RsaGenerator{}
}

var NewEccGenerator = func() Generator {
	return &EccGenerator{}
}

// RsaGenerator implements Generator interface
type RsaGenerator struct{}

func (g *RsaGenerator) GenerateKeyPair() (KeyPair, error) {
	return g.generate()
}

// generate generates a new RSAKeyPair.
func (g *RsaGenerator) generate() (*rsaKeyPair, error) {
	// Security has been ignored for the sake of simplicity.
	key, err := rsa.GenerateKey(rand.Reader, 512)
	if err != nil {
		return nil, err
	}

	return &rsaKeyPair{
		Public:  &key.PublicKey,
		Private: key,
	}, nil
}

// EccGenerator implements Generator interface
type EccGenerator struct{}

func (g *EccGenerator) GenerateKeyPair() (KeyPair, error) {
	return g.generate()
}

// generate generates a new ECCKeyPair.
func (g *EccGenerator) generate() (*eccKeyPair, error) {
	// Security has been ignored for the sake of simplicity.
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	return &eccKeyPair{
		Public:  &key.PublicKey,
		Private: key,
	}, nil
}
