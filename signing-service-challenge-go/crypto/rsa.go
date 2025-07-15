package crypto

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

var NewRSAMarshaler = func() Marshaler {
	return newRSAMarshaler()
}

var ErrInvalidKeyPairType = errors.New("invalid key pair type")

// rsaKeyPair is a DTO that holds RSA private and public keys.
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

// rsaMarshaler can encode and decode an RSA key pair.
type rsaMarshaler struct{}

// NewRSAMarshaler creates a new RSAMarshaler.
func newRSAMarshaler() *rsaMarshaler {
	return &rsaMarshaler{}
}

// Implement Marshaler for type rsaMarshaler
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

// rsaCryptoOperations is a struct that implements the CryptoOperations interface
type rsaCryptoOperations struct {
	KeyPair
	Generator
	Marshaler
}

func (r *rsaCryptoOperations) Algorithm() Algorithm {
	return AlgorithmRSA
}

// EncodeKeyPair encodes the RSA key pair into public and private key byte slices.
func (r *rsaCryptoOperations) EncodeKeyPair() ([]byte, []byte, error) {
	publicKey, privateKey, err := r.Marshaler.Encode(r.KeyPair)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

// DecodeKeyPair decodes the RSA private key bytes into an RSAKeyPair.
func (r *rsaCryptoOperations) DecodeKeyPair() (KeyPair, error) {
	keyPair, err := r.Marshaler.Decode(r.KeyPair.GetPrivate().([]byte))
	if err != nil {
		return nil, err
	}

	if _, ok := keyPair.(*rsaKeyPair); !ok {
		return nil, ErrInvalidKeyPairType
	}

	return keyPair, nil
}
