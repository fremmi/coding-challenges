package persistence

import (
	"encoding/json"
	"errors"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
)

var ErrDeviceAlreadyExists = errors.New("device already exists")

type PersistedDevice struct {
	ID         string           `json:"id"`
	Label      string           `json:"label"`
	Algorithm  crypto.Algorithm `json:"algorithm"` // "RSA" or "ECC" so far
	Counter    int64            `json:"counter"`
	PrivatePEM []byte           `json:"private_key"` // PEM-encoded private key
	PublicPem  []byte           `json:"public_key"`  // PEM-encoded public key
}

// Create a persistent representation of the Device.
func Persisted(d *domain.Device) ([]byte, error) {
	persistedDevice := PersistedDevice{
		ID:        d.Id,
		Label:     d.Label,
		Algorithm: d.Algorithm,
		Counter:   d.Counter,
	}

	if d.KeyPair == nil || d.Marshaler == nil {
		return nil, crypto.ErrUnsupportedAlgorithm
	}

	persistedDevice.PrivatePEM, persistedDevice.PublicPem, _ = d.Marshaler.Encode(d.KeyPair)

	// serialize persistedDevice to JSON
	return json.Marshal(persistedDevice)
}

// RestoreDevice restores a Device from its persisted JSON representation.
func RestoreDevice(persisted []byte) (*domain.Device, error) {
	var d = &domain.Device{}
	var persistedDevice PersistedDevice
	if err := json.Unmarshal(persisted, &persistedDevice); err != nil {
		return nil, err
	}

	d.Id = persistedDevice.ID
	d.Label = persistedDevice.Label
	d.Algorithm = persistedDevice.Algorithm
	d.Counter = persistedDevice.Counter

	switch persistedDevice.Algorithm {
	case crypto.AlgorithmRSA:
		d.Marshaler = crypto.NewRSAMarshaler()
		d.Generator = &crypto.RsaGenerator{}
	case crypto.AlgorithmECC:
		d.Marshaler = crypto.NewECCMarshaler()
		d.Generator = &crypto.EccGenerator{}
	default:
		return nil, crypto.ErrUnsupportedAlgorithm

	}

	var err error
	if d.KeyPair, err = d.Marshaler.Decode(persistedDevice.PrivatePEM); err != nil {
		return nil, err
	}

	d.Signer = crypto.NewSigner(d.Algorithm, d.KeyPair)
	return d, nil
}

type DeviceManager struct {
	devices map[string]*domain.Device
}

func NewDeviceManager() *DeviceManager {
	return &DeviceManager{
		devices: make(map[string]*domain.Device),
	}
}

// AddDevice adds a new device to the DeviceManager.
// We assume that id is unique, meaning that the same id cannot be used for multiple algorithms
func (dm *DeviceManager) AddDevice(id string, algo crypto.Algorithm, label string) (*domain.Device, error) {
	if _, exists := dm.devices[id]; exists {
		return nil, ErrDeviceAlreadyExists
	}

	device, err := domain.NewDevice(id, label, algo)
	if err != nil {
		return nil, err
	}

	dm.devices[id] = device
	return device, nil
}

func (dm *DeviceManager) GetDevice(id string) (*domain.Device, error) {
	if device, exists := dm.devices[id]; exists {
		return device, nil
	}
	return nil, errors.New("device not found")
}

// StoreDevices stores all devices in the DeviceManager to a persistent storage.
// NOT FULLY IMPLEMENTED
func (dm *DeviceManager) StoreDevices() {
	for _, device := range dm.devices {
		persisted, err := Persisted(device)
		if err != nil {
			continue // handle error appropriately in production code
		}

		_ = persisted

		// Some logic here to store on a persistent storage. TBD
	}
}

// RestoreDevices restores all devices from a persistent storage to the DeviceManager.
// This is just an example of serialiazing and deserializing devices. NOT FULLY implemented yet.
func (dm *DeviceManager) RestoreDevices() {
	// Some logic here to restore from a persistent storage. TBD
	// For now, we will just return an empty map.
	dm.devices = make(map[string]*domain.Device)
	// Let's pretend we got some persisted data from a storage

	var persistedData = [][]byte{}
	for _, persisted := range persistedData { // This should be replaced with actual persisted data

		device, err := RestoreDevice(persisted)
		if err != nil {
			continue // handle error appropriately in production code
		}
		dm.devices[device.Id] = device
	}
}
