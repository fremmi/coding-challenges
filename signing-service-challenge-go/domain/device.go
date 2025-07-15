package domain

import (
	"encoding/json"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
)

type Device struct {
	Id    string
	Label string

	Algorithm crypto.Algorithm
	keyPair   crypto.KeyPair
	marshaler crypto.Marshaler
	generator crypto.Generator

	Counter int64
}

func NewDevice(id, label string, algo crypto.Algorithm) (*Device, error) {
	var d = &Device{
		Id:        id,
		Label:     label,
		Algorithm: algo,
		Counter:   0,
	}

	switch algo {
	case crypto.AlgorithmRSA:
		d.marshaler = crypto.NewRSAMarshaler()
		d.generator = &crypto.RsaGenerator{}
	case crypto.AlgorithmECC:
		d.marshaler = crypto.NewECCMarshaler()
		d.generator = &crypto.EccGenerator{}
	default:
		return nil, crypto.ErrUnsupportedAlgorithm
	}

	var err error
	if d.keyPair, err = d.generator.GenerateKeyPair(); err != nil {
		return nil, err
	}

	return d, nil
}

// Create a persistent representation of the Device.
func (d *Device) Persisted() ([]byte, error) {
	persistedDevice := persistence.PersistedDevice{
		ID:        d.Id,
		Label:     d.Label,
		Algorithm: d.Algorithm,
		Counter:   d.Counter,
	}

	if d.keyPair == nil || d.marshaler == nil {
		return nil, crypto.ErrUnsupportedAlgorithm
	}

	persistedDevice.PrivatePEM, persistedDevice.PublicPem, _ = d.marshaler.Encode(d.keyPair)

	// serialize persistedDevice to JSON
	return json.Marshal(persistedDevice)
}

// RestoreDevice restores a Device from its persisted JSON representation.
func RestoreDevice(persisted []byte) (*Device, error) {
	var d = &Device{}
	var persistedDevice persistence.PersistedDevice
	if err := json.Unmarshal(persisted, &persistedDevice); err != nil {
		return nil, err
	}

	d.Id = persistedDevice.ID
	d.Label = persistedDevice.Label
	d.Algorithm = persistedDevice.Algorithm
	d.Counter = persistedDevice.Counter

	switch persistedDevice.Algorithm {
	case crypto.AlgorithmRSA:
		d.marshaler = crypto.NewRSAMarshaler()
		d.generator = &crypto.RsaGenerator{}
	case crypto.AlgorithmECC:
		d.marshaler = crypto.NewECCMarshaler()
		d.generator = &crypto.EccGenerator{}
	default:
		return nil, crypto.ErrUnsupportedAlgorithm

	}

	var err error
	if d.keyPair, err = d.marshaler.Decode(persistedDevice.PrivatePEM); err != nil {
		return nil, err
	}

	return d, nil
}
