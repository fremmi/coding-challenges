package crypto

import (
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
)

// A builder function for creating a new ECCMarshaler.
// useful for testing or when you want to use a different implementation.
var NewECCMarshaler = func() Marshaler {
	return newECCMarshaler()
}

// eccKeyPair is a DTO that holds ECC private and public keys.
type eccKeyPair struct {
	Public  *ecdsa.PublicKey
	Private *ecdsa.PrivateKey
}

// Implement KeyPair interface for ECCKeyPair
func (e *eccKeyPair) GetPrivate() any {
	return e.Private
}

func (e *eccKeyPair) GetPublic() any {
	return e.Public
}

// eccMarshaler can encode and decode an ECC key pair.
type eccMarshaler struct{}

// NewECCMarshaler creates a new ECCMarshaler.
func newECCMarshaler() *eccMarshaler {
	return &eccMarshaler{}
}

// Implement Marshaler for type eccMarshaler
func (m *eccMarshaler) Encode(keyPair KeyPair) ([]byte, []byte, error) {
	if _, ok := keyPair.(*eccKeyPair); !ok {
		return nil, nil, ErrInvalidKeyPairType
	}

	return m.marshal(keyPair.(*eccKeyPair))
}

func (m *eccMarshaler) Decode(privateKeyBytes []byte) (KeyPair, error) {
	keyPair, err := m.unmarshal(privateKeyBytes)
	if err != nil {
		return nil, err
	}
	return keyPair, nil
}

// Encode takes an ECCKeyPair and encodes it to be written on disk.
// It returns the public and the private key as a byte slice.
func (m eccMarshaler) marshal(keyPair *eccKeyPair) ([]byte, []byte, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(keyPair.Private)
	if err != nil {
		return nil, nil, err
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(keyPair.Public)
	if err != nil {
		return nil, nil, err
	}

	encodedPrivate := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE_KEY",
		Bytes: privateKeyBytes,
	})

	encodedPublic := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC_KEY",
		Bytes: publicKeyBytes,
	})

	return encodedPublic, encodedPrivate, nil
}

// unmarshal assembles an ECCKeyPair from an encoded private key.
func (m eccMarshaler) unmarshal(privateKeyBytes []byte) (*eccKeyPair, error) {
	block, _ := pem.Decode(privateKeyBytes)
	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return &eccKeyPair{
		Private: privateKey,
		Public:  &privateKey.PublicKey,
	}, nil
}

// eccCryptoOperations implements the CryptoOperations interface for ECC.
type eccCryptoOperations struct {
	KeyPair
	Generator
	Marshaler
}

func (ecc *eccCryptoOperations) Algorithm() Algorithm {
	return AlgorithmECC
}

// EncodeKeyPair encodes the ECC key pair into public and private key byte slices.
func (ecc *eccCryptoOperations) EncodeKeyPair() ([]byte, []byte, error) {
	publicKey, privateKey, err := ecc.Marshaler.Encode(ecc.KeyPair)
	if err != nil {
		return nil, nil, err
	}
	return publicKey, privateKey, nil
}

func (ecc *eccCryptoOperations) DecodeKeyPair() (KeyPair, error) {
	keyPair, err := ecc.Marshaler.Decode(ecc.KeyPair.GetPrivate().([]byte))
	if err != nil {
		return nil, err
	}
	return keyPair, nil
}
