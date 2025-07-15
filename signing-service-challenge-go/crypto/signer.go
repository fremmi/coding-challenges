package crypto

import (
	cr "crypto"
	"crypto/ecdsa"
	"crypto/rand"
	rsa "crypto/rsa"
	"crypto/sha256"
)

// Builder functions. Useful for testing or when you want to use a different implementation.
var NewSigner = func(algo Algorithm, keys KeyPair) Signer {
	return newSigner(algo, keys)
}

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	Sign(dataToBeSigned []byte) ([]byte, error)
}

// rsaSigner implements the Signer interface for RSA keys.
type rsaSigner struct {
	rsaKeyPair *rsaKeyPair
}

func newSigner(algo Algorithm, keys KeyPair) Signer {
	switch algo {
	case AlgorithmRSA:
		if rsaKeyPair, ok := keys.(*rsaKeyPair); ok {
			return &rsaSigner{rsaKeyPair: rsaKeyPair}
		}
	case AlgorithmECC:
		if eccKeyPair, ok := keys.(*eccKeyPair); ok {
			return &eccSigner{eccKeyPair: eccKeyPair}
		}
	default:
		return nil
	}
	return nil
}

func (r *rsaSigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	hashed := sha256.Sum256(dataToBeSigned)

	signature, err := rsa.SignPKCS1v15(rand.Reader, r.rsaKeyPair.Private, cr.SHA256, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// eccSigner implements the Signer interface for ECC keys.
type eccSigner struct {
	eccKeyPair *eccKeyPair
}

func (e *eccSigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	hashed := sha256.Sum256(dataToBeSigned)

	signature, err := ecdsa.SignASN1(rand.Reader, e.eccKeyPair.Private, hashed[:])
	if err != nil {
		return nil, err
	}
	return signature, nil
}
