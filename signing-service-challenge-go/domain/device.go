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
	Operator  crypto.CryptoOperations

	keyPair crypto.KeyPair
	Counter int64
}

func (d *Device) Persisted() ([]byte, error) {
	persistedDevice := persistence.PersistedDevice{
		ID:        d.Id,
		Label:     d.Label,
		Algorithm: d.Algorithm,
		Counter:   d.Counter,
	}

	persistedDevice.PrivatePEM, persistedDevice.PublicPem, _ = d.Operator.EncodeKeyPair()

	// serialize persistedDevice to JSON
	return json.Marshal(persistedDevice)
}

// RestoreDevice restores a Device from its persisted JSON representation.
func RestoreDevice(persisted []byte) (*Device, error) {
	var d Device
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
		d.Operator = crypto.NewRsaCryptoOperations()
	case crypto.AlgorithmECC:
		d.Operator = crypto.NewECCryptoOperations()
	default:
		return nil, crypto.ErrUnsupportedAlgorithm

	}

	if (keyPair, err := d.Operator.Decode(persistedDevice.PrivatePEM); err != nil {
		return nil, err
	} else {
		d.keyPair = keyPair
	}
}
