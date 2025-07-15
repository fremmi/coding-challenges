package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// RsaGenerator generates a RSA key pair.
type RsaGenerator struct{}

// Implement Generator for type RSAKeyPair
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

// EccGenerator generates an ECC key pair.
type EccGenerator struct{}

// Implement Generator for type ECCKeyPair
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
