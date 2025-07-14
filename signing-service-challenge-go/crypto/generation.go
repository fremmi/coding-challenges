package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
)

// rsaGenerator generates a RSA key pair.
type rsaGenerator struct{}

// Implement Generator for type RSAKeyPair
func (g *rsaGenerator) GenerateKeyPair() (KeyPair, error) {
	return g.generate()
}

// generate generates a new RSAKeyPair.
func (g *rsaGenerator) generate() (*rsaKeyPair, error) {
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

// eccGenerator generates an ECC key pair.
type eccGenerator struct{}

// Implement Generator for type ECCKeyPair
func (g *eccGenerator) GenerateKeyPair() (KeyPair, error) {
	return g.generate()
}

// generate generates a new ECCKeyPair.
func (g *eccGenerator) generate() (*eccKeyPair, error) {
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
