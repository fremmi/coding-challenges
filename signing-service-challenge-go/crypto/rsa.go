package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// A builder function for creating a new Marshaler. Useful for testing or when you want to use a different implementation.
var NewRSAMarshaler = func() Marshaler {
	return newRSAMarshaler()
}

var ErrInvalidKeyPairType = errors.New("invalid key pair type")

// rsaKeyPair implements KeyPair interface
type rsaKeyPair struct {
	Public  *rsa.PublicKey
	Private *rsa.PrivateKey
}

// Implement KeyPair interface for RSAKeyPair
func (r *rsaKeyPair) GetPrivate() any {
	return r.Private
}

func (r *rsaKeyPair) GetPublic() any {
	return r.Public
}

// rsaMarshaler implements Marshaler interface
type rsaMarshaler struct{}

// newRSAMarshaler creates a new RSAMarshaler.
func newRSAMarshaler() *rsaMarshaler {
	return &rsaMarshaler{}
}

func (m *rsaMarshaler) Encode(keyPair KeyPair) ([]byte, []byte, error) {
	if _, ok := keyPair.(*rsaKeyPair); !ok {
		return nil, nil, ErrInvalidKeyPairType
	}

	return m.marshal(keyPair.(*rsaKeyPair))

}

func (m *rsaMarshaler) Decode(privateKeyBytes []byte) (KeyPair, error) {
	keyPair, err := m.unmarshal(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	return keyPair, nil
}

// marshal takes an RSAKeyPair and encodes it to be written on disk.
// It returns the public and the private key as a byte slice.
func (m *rsaMarshaler) marshal(keyPair *rsaKeyPair) ([]byte, []byte, error) {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(keyPair.Private)
	publicKeyBytes := x509.MarshalPKCS1PublicKey(keyPair.Public)

	encodedPrivate := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA_PRIVATE_KEY",
		Bytes: privateKeyBytes,
	})

	encodePublic := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA_PUBLIC_KEY",
		Bytes: publicKeyBytes,
	})

	return encodePublic, encodedPrivate, nil
}

// unmarshal takes an encoded RSA private key and transforms it into a rsa.PrivateKey.
func (m *rsaMarshaler) unmarshal(privateKeyBytes []byte) (*rsaKeyPair, error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &rsaKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}
