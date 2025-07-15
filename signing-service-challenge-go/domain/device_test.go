package domain_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto" // Adjust this import path if necessary
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain" // Adjust this import path if necessary
	"github.com/stretchr/testify/assert"                                    // Using testify for cleaner assertions
	"github.com/stretchr/testify/mock"                                      // Using testify/mock for mocking interfaces
	"k8s.io/klog"
	// For klog setup
)

var errMockGenerator = errors.New("mock generator error")

// --- Mocks for Crypto Interfaces ---

// MockKeyPair implements crypto.KeyPair
type MockKeyPair struct {
	mock.Mock
}

func (m *MockKeyPair) GetPrivate() any {
	args := m.Called()
	return args.Get(0)
}

func (m *MockKeyPair) GetPublic() any {
	args := m.Called()
	return args.Get(0)
}

// MockMarshaler implements crypto.Marshaler
type MockMarshaler struct {
	mock.Mock
}

func (m *MockMarshaler) Encode(keyPair crypto.KeyPair) ([]byte, []byte, error) {
	args := m.Called(keyPair)
	return args.Get(0).([]byte), args.Get(1).([]byte), args.Error(2)
}

func (m *MockMarshaler) Decode(privateKeyBytes []byte) (crypto.KeyPair, error) {
	args := m.Called(privateKeyBytes)
	return args.Get(0).(crypto.KeyPair), args.Error(1)
}

// MockGenerator implements crypto.Generator
type MockGenerator struct {
	mock.Mock
}

func (m *MockGenerator) GenerateKeyPair() (crypto.KeyPair, error) {
	args := m.Called()
	return args.Get(0).(crypto.KeyPair), args.Error(1)
}

// MockSigner implements crypto.Signer
type MockSigner struct {
	mock.Mock
}

func (m *MockSigner) Sign(data []byte) ([]byte, error) {
	args := m.Called(data)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockSigner) Algorithm() crypto.Algorithm {
	args := m.Called()
	return args.Get(0).(crypto.Algorithm)
}

func TestMain(m *testing.M) {
	// Disable klog output during tests, or redirect it to /dev/null
	// klog.SetOutput(io.Discard) // Or use a testing.T logger
	klog.SetOutput(new(mockLogWriter)) // Redirect klog to a no-op writer

	// Run tests
	code := m.Run()

	os.Exit(code)
}

type mockLogWriter struct{}

func (m *mockLogWriter) Write(p []byte) (n int, err error) {
	// Discard all log messages
	return len(p), nil
}

// --- Tests for NewDevice ---
func TestNewDevice(t *testing.T) {
	// Save original implementations to restore later
	originalNewRSAMarshaler := crypto.NewRSAMarshaler
	originalNewECCMarshaler := crypto.NewECCMarshaler
	originalNewRsaGenerator := crypto.NewRsaGenerator
	originalNewEccGenerator := crypto.NewEccGenerator
	originalNewSigner := crypto.NewSigner

	// Restore original implementations after tests
	defer func() {
		crypto.NewRSAMarshaler = originalNewRSAMarshaler
		crypto.NewECCMarshaler = originalNewECCMarshaler
		crypto.NewRsaGenerator = originalNewRsaGenerator
		crypto.NewEccGenerator = originalNewEccGenerator
		crypto.NewSigner = originalNewSigner
	}()

	mockKeyPair := new(MockKeyPair)
	mockKeyPair.On("GetPrivate").Return(nil) // Mock GetPrivate/Public just to satisfy interface
	mockKeyPair.On("GetPublic").Return(nil)

	mockGenerator := new(MockGenerator)
	mockGenerator.On("GenerateKeyPair").Return(mockKeyPair, nil)

	mockMarshalerRSA := new(MockMarshaler)
	mockMarshalerECC := new(MockMarshaler)

	mockSigner := new(MockSigner)
	mockSigner.On("Algorithm").Return(crypto.AlgorithmRSA) // Or ECC, depending on the test case

	// Mock the constructor functions that NewDevice calls
	crypto.NewRSAMarshaler = func() crypto.Marshaler { return mockMarshalerRSA }
	crypto.NewECCMarshaler = func() crypto.Marshaler { return mockMarshalerECC }
	crypto.NewRsaGenerator = func() crypto.Generator { return mockGenerator }
	crypto.NewEccGenerator = func() crypto.Generator { return mockGenerator }
	crypto.NewSigner = func(algo crypto.Algorithm, kp crypto.KeyPair) crypto.Signer { return mockSigner }

	tests := []struct {
		name          string
		id            string
		label         string
		algorithm     crypto.Algorithm
		expectedError error
		assertFunc    func(*testing.T, *domain.Device)
	}{
		{
			name:      "New RSA Device Success",
			id:        "rsa-device-1",
			label:     "RSA Tester",
			algorithm: crypto.AlgorithmRSA,
			assertFunc: func(t *testing.T, d *domain.Device) {
				if d != nil {
					assert.NotNil(t, d)
					assert.Equal(t, "rsa-device-1", d.Id)
					assert.Equal(t, "RSA Tester", d.Label)
					assert.Equal(t, crypto.AlgorithmRSA, d.Algorithm)
					assert.Equal(t, int64(0), d.Counter)
					assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("rsa-device-1")), d.LastSignature)
					assert.NotNil(t, d.KeyPair)
					assert.NotNil(t, d.Marshaler)
					assert.NotNil(t, d.Generator)
					assert.NotNil(t, d.Signer)
					assert.NotNil(t, d.Transactions)
					assert.Empty(t, d.Transactions)
				}
			},
		},
		{
			name:      "New ECC Device Success",
			id:        "ecc-device-1",
			label:     "ECC Tester",
			algorithm: crypto.AlgorithmECC,
			assertFunc: func(t *testing.T, d *domain.Device) {
				if d != nil {
					assert.NotNil(t, d)
					assert.Equal(t, "ecc-device-1", d.Id)
					assert.Equal(t, "ECC Tester", d.Label)
					assert.Equal(t, crypto.AlgorithmECC, d.Algorithm)
					assert.Equal(t, int64(0), d.Counter)
					assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("ecc-device-1")), d.LastSignature)
					assert.NotNil(t, d.KeyPair)
					assert.NotNil(t, d.Marshaler)
					assert.NotNil(t, d.Generator)
					assert.NotNil(t, d.Signer)
					assert.NotNil(t, d.Transactions)
					assert.Empty(t, d.Transactions)
				}
			},
		},
		{
			name:          "Unsupported Algorithm",
			id:            "bad-device",
			label:         "Unknown Algo",
			algorithm:     "UNKNOWN",
			expectedError: crypto.ErrUnsupportedAlgorithm,
		},
		{
			name:          "Generator Error",
			id:            "err-device",
			label:         "Gen Error",
			algorithm:     crypto.AlgorithmRSA,
			expectedError: errMockGenerator,
			assertFunc: func(t *testing.T, d *domain.Device) {
				// Reconfigure mock to return error for this specific test case
				mockGenerator.ExpectedCalls = nil // Clear previous expectations
				mockGenerator.On("GenerateKeyPair").Return(mockKeyPair, errMockGenerator).Once()
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// If assertFunc is provided, it might set up mock expectations for this specific test
			if tc.assertFunc != nil {
				tc.assertFunc(t, nil) // Pass nil for device, as it's not created yet, just to set up mocks
			}

			device, err := domain.NewDevice(tc.id, tc.label, tc.algorithm)

			if tc.expectedError != nil {
				assert.Error(t, err)
				assert.True(t, errors.Is(err, tc.expectedError), "Expected error %v, got %v", tc.expectedError, err)
				assert.Nil(t, device)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, device)
				tc.assertFunc(t, device) // Re-run assertFunc to verify device state
			}
			mockGenerator.AssertExpectations(t) // Verify mock was called as expected
		})
	}
}

// --- Tests for SignTransaction ---
func TestDevice_SignTransaction(t *testing.T) {
	// Save original implementations to restore later
	originalNewRSAMarshaler := crypto.NewRSAMarshaler
	originalNewECCMarshaler := crypto.NewECCMarshaler
	originalNewRsaGenerator := crypto.NewRsaGenerator
	originalNewEccGenerator := crypto.NewEccGenerator
	originalNewSigner := crypto.NewSigner

	// Mock necessary dependencies for a Device
	mockKeyPair := new(MockKeyPair)
	mockKeyPair.On("GetPrivate").Return(nil)
	mockKeyPair.On("GetPublic").Return(nil)

	mockMarshaler := new(MockMarshaler)
	mockGenerator := new(MockGenerator)
	mockGenerator.On("GenerateKeyPair").Return(mockKeyPair, nil) // Device creation needs this

	mockSigner := new(MockSigner)

	// Stub out the global functions that NewDevice calls
	crypto.NewRSAMarshaler = func() crypto.Marshaler { return mockMarshaler }
	crypto.NewECCMarshaler = func() crypto.Marshaler { return mockMarshaler }
	crypto.NewRsaGenerator = func() crypto.Generator { return mockGenerator }
	crypto.NewEccGenerator = func() crypto.Generator { return mockGenerator }
	crypto.NewSigner = func(algo crypto.Algorithm, kp crypto.KeyPair) crypto.Signer { return mockSigner }

	defer func() { // Restore originals
		crypto.NewRSAMarshaler = originalNewRSAMarshaler
		crypto.NewECCMarshaler = originalNewECCMarshaler
		crypto.NewRsaGenerator = originalNewRsaGenerator
		crypto.NewEccGenerator = originalNewEccGenerator
		crypto.NewSigner = originalNewSigner
	}()

	// Create a new device for testing
	device, err := domain.NewDevice("test-device-id", "Test Device", crypto.AlgorithmRSA)
	assert.NoError(t, err)
	assert.NotNil(t, device)

	t.Run("Successful Signing", func(t *testing.T) {
		transactionData := "my-transaction-data-123"
		expectedSignature := []byte("mock-signature-bytes-1")
		expectedSignatureBase64 := base64.StdEncoding.EncodeToString(expectedSignature)

		// Expected data to be signed: 0_my-transaction-data-123_base64encoded(device.Id)
		initialLastSignature := base64.StdEncoding.EncodeToString([]byte(device.Id))
		expectedSignedData := fmt.Sprintf("0_%s_%s", transactionData, initialLastSignature)

		mockSigner.On("Sign", []byte(expectedSignedData)).Return(expectedSignature, nil).Once()

		signature, data, err := device.SignTransaction(transactionData)

		assert.NoError(t, err)
		assert.Equal(t, expectedSignatureBase64, signature)
		assert.Equal(t, expectedSignedData, data)
		assert.Equal(t, int64(1), device.Counter)
		assert.Equal(t, expectedSignatureBase64, device.LastSignature)
		assert.Len(t, device.ListTransactions(), 1)
		assert.Equal(t, domain.Transaction{Signature: expectedSignatureBase64, Data: expectedSignedData}, device.Transactions[0])

		mockSigner.AssertExpectations(t)
	})

	t.Run("Signing Error", func(t *testing.T) {
		transactionData := "another-transaction"
		expectedErr := fmt.Errorf("signer error")

		// Calculate expected data based on current device state (counter 1, last signature from previous test)
		currentLastSignature := device.LastSignature
		expectedSignedData := fmt.Sprintf("%d_%s_%s", device.Counter, transactionData, currentLastSignature)

		mockSigner.On("Sign", []byte(expectedSignedData)).Return([]byte{}, expectedErr).Once()

		signature, data, err := device.SignTransaction(transactionData)

		assert.Error(t, err)
		assert.True(t, errors.Is(err, expectedErr))
		assert.Empty(t, signature)
		assert.Empty(t, data)
		// Counter, lastSignature, transactions should NOT change on error
		assert.Equal(t, int64(1), device.Counter) // Still 1 from previous successful test
		assert.Equal(t, currentLastSignature, device.LastSignature)
		assert.Len(t, device.ListTransactions(), 1) // Still 1 transaction
		// Ensure no new transaction was added for this failed attempt
		assert.NotContains(t, device.Transactions, device.Counter)

		mockSigner.AssertExpectations(t)
	})

	t.Run("Concurrent Signing", func(t *testing.T) {
		numGoroutines := 100
		var wg sync.WaitGroup
		initialCounter := device.Counter // Should be 1 from previous tests

		for i := 0; i < numGoroutines; i++ {
			wg.Add(1)
			go func(index int) {
				defer wg.Done()
				txnData := fmt.Sprintf("concurrent-txn-%d", index)
				mockSigner.On("Sign", mock.AnythingOfType("[]uint8")).Return([]byte(fmt.Sprintf("sig-%d", index)), nil).Once()

				sig, data, err := device.SignTransaction(txnData)

				assert.NoError(t, err)
				assert.NotEmpty(t, sig)
				assert.NotEmpty(t, data)
			}(i)
		}
		wg.Wait()

		// Verify the final state after all concurrent calls
		assert.Equal(t, initialCounter+int64(numGoroutines), device.Counter)
		assert.Len(t, device.ListTransactions(), int(initialCounter+int64(numGoroutines)))
		// We can't easily assert on individual transaction data due to concurrent ordering
		// but we can check the total count and that keys exist.
	})
}

// --- Tests for ListTransactions ---
func TestDevice_ListTransactions(t *testing.T) {
	// Create a new device for testing (mocking setup similar to SignTransaction)
	mockKeyPair := new(MockKeyPair)
	mockKeyPair.On("GetPrivate").Return(nil)
	mockKeyPair.On("GetPublic").Return(nil)
	mockMarshaler := new(MockMarshaler)
	mockGenerator := new(MockGenerator)
	mockGenerator.On("GenerateKeyPair").Return(mockKeyPair, nil)
	mockSigner := new(MockSigner)

	originalNewRSAMarshaler := crypto.NewRSAMarshaler
	originalNewECCMarshaler := crypto.NewECCMarshaler
	originalNewRsaGenerator := crypto.NewRsaGenerator
	originalNewEccGenerator := crypto.NewEccGenerator
	originalNewSigner := crypto.NewSigner
	defer func() {
		crypto.NewRSAMarshaler = originalNewRSAMarshaler
		crypto.NewECCMarshaler = originalNewECCMarshaler
		crypto.NewRsaGenerator = originalNewRsaGenerator
		crypto.NewEccGenerator = originalNewEccGenerator
		crypto.NewSigner = originalNewSigner
	}()
	crypto.NewRSAMarshaler = func() crypto.Marshaler { return mockMarshaler }
	crypto.NewECCMarshaler = func() crypto.Marshaler { return mockMarshaler }
	crypto.NewRsaGenerator = func() crypto.Generator { return mockGenerator }
	crypto.NewEccGenerator = func() crypto.Generator { return mockGenerator }
	crypto.NewSigner = func(algo crypto.Algorithm, kp crypto.KeyPair) crypto.Signer { return mockSigner }

	device, err := domain.NewDevice("list-test-id", "List Device", crypto.AlgorithmRSA)
	assert.NoError(t, err)

	t.Run("Empty transactions", func(t *testing.T) {
		transactions := device.ListTransactions()
		assert.Empty(t, transactions)
	})

	t.Run("Transactions after signing", func(t *testing.T) {
		// Sign a few transactions
		mockSigner.On("Sign", mock.AnythingOfType("[]uint8")).Return([]byte("sig1"), nil).Once()
		_, _, err := device.SignTransaction("txn1")
		assert.NoError(t, err)

		mockSigner.On("Sign", mock.AnythingOfType("[]uint8")).Return([]byte("sig2"), nil).Once()
		_, _, err = device.SignTransaction("txn2")
		assert.NoError(t, err)

		transactions := device.ListTransactions()
		assert.Len(t, transactions, 2)
		// The order of elements returned from iterating a map is not guaranteed,
		// so check for existence of expected data.
		expectedTxn1 := domain.Transaction{Signature: base64.StdEncoding.EncodeToString([]byte("sig1")), Data: fmt.Sprintf("0_txn1_%s", base64.StdEncoding.EncodeToString([]byte("list-test-id")))}
		expectedTxn2 := domain.Transaction{Signature: base64.StdEncoding.EncodeToString([]byte("sig2")), Data: fmt.Sprintf("1_txn2_%s", base64.StdEncoding.EncodeToString([]byte("sig1")))}

		assert.Contains(t, transactions, expectedTxn1)
		assert.Contains(t, transactions, expectedTxn2)

		mockSigner.AssertExpectations(t)
	})
}

// --- Tests for GetTransaction ---
func TestDevice_GetTransaction(t *testing.T) {
	// Create a new device for testing (mocking setup similar to SignTransaction)
	mockKeyPair := new(MockKeyPair)
	mockKeyPair.On("GetPrivate").Return(nil)
	mockKeyPair.On("GetPublic").Return(nil)
	mockMarshaler := new(MockMarshaler)
	mockGenerator := new(MockGenerator)
	mockGenerator.On("GenerateKeyPair").Return(mockKeyPair, nil)
	mockSigner := new(MockSigner)

	originalNewRSAMarshaler := crypto.NewRSAMarshaler
	originalNewECCMarshaler := crypto.NewECCMarshaler
	originalNewRsaGenerator := crypto.NewRsaGenerator
	originalNewEccGenerator := crypto.NewEccGenerator
	originalNewSigner := crypto.NewSigner
	defer func() {
		crypto.NewRSAMarshaler = originalNewRSAMarshaler
		crypto.NewECCMarshaler = originalNewECCMarshaler
		crypto.NewRsaGenerator = originalNewRsaGenerator
		crypto.NewEccGenerator = originalNewEccGenerator
		crypto.NewSigner = originalNewSigner
	}()
	crypto.NewRSAMarshaler = func() crypto.Marshaler { return mockMarshaler }
	crypto.NewECCMarshaler = func() crypto.Marshaler { return mockMarshaler }
	crypto.NewRsaGenerator = func() crypto.Generator { return mockGenerator }
	crypto.NewEccGenerator = func() crypto.Generator { return mockGenerator }
	crypto.NewSigner = func(algo crypto.Algorithm, kp crypto.KeyPair) crypto.Signer { return mockSigner }

	device, err := domain.NewDevice("get-test-id", "Get Device", crypto.AlgorithmRSA)
	assert.NoError(t, err)

	// Sign some transactions to populate the map
	mockSigner.On("Sign", mock.AnythingOfType("[]uint8")).Return([]byte("sigA"), nil).Once()
	_, _, err = device.SignTransaction("first-txn")
	assert.NoError(t, err) // Counter is 0, sigA, data0

	mockSigner.On("Sign", mock.AnythingOfType("[]uint8")).Return([]byte("sigB"), nil).Once()
	_, _, err = device.SignTransaction("second-txn")
	assert.NoError(t, err) // Counter is 1, sigB, data1

	mockSigner.On("Sign", mock.AnythingOfType("[]uint8")).Return([]byte("sigC"), nil).Once()
	_, _, err = device.SignTransaction("third-txn")
	assert.NoError(t, err) // Counter is 2, sigC, data2

	t.Run("Get existing transaction", func(t *testing.T) {
		txn, err := device.GetTransaction(1)
		assert.NoError(t, err)
		expectedData := fmt.Sprintf("1_second-txn_%s", base64.StdEncoding.EncodeToString([]byte("sigA")))
		assert.Equal(t, domain.Transaction{Signature: base64.StdEncoding.EncodeToString([]byte("sigB")), Data: expectedData}, txn)
	})

	t.Run("Get non-existing transaction (index too high)", func(t *testing.T) {
		txn, err := device.GetTransaction(100) // Only 3 transactions exist (0, 1, 2)
		assert.Error(t, err)
		assert.Equal(t, "Transaction does not exist", err.Error())
		assert.Equal(t, domain.Transaction{}, txn) // Should return zero value
	})

	t.Run("Get non-existing transaction (negative index)", func(t *testing.T) {
		txn, err := device.GetTransaction(-1)
		assert.Error(t, err)
		assert.Equal(t, "Transaction does not exist", err.Error())
		assert.Equal(t, domain.Transaction{}, txn)
	})

	mockSigner.AssertExpectations(t)
}
