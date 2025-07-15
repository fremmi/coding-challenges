package crypto

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	Sign(dataToBeSigned []byte) ([]byte, error)
}

// Notice. Instead of implementing the Signer interface directly,
// I choose to implement the CryptoOperations interface which embodies
// KeyPair, Generator, and Marshaler contracts.
