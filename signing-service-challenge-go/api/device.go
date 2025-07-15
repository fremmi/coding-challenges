package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
)

// Types defining HTTP request and responses
// For convenience, only POST method is used for all requests,
// even for those that could be GET requests.
type CreateSignatureDeviceResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type CreateSignatureRequestBody struct {
	ID        string           `json:"id"`
	Algorithm crypto.Algorithm `json:"algorithm"` // "RSA" or "ECC"
	Label     string           `json:"label"`
}

type SignTransactionResponse struct {
	Signature  string `json:"signature"`
	Error      string `json:"error,omitempty"`
	SignedData string `json:"signed_data,omitempty"`
}

type SignTransactionRequestBody struct {
	ID          string `json:"id"`
	Transaction string `json:"transaction"`
}

type ListTransactionsRequestBody struct {
	ID string `json:"id"`
}

type ListTransactionsResponse struct {
	Transactions []SignTransactionResponse `json:"transactions"`
}

type GetTransactionRequestBody struct {
	DeviceID      string `json:"device_id"`
	TransactionID string `json:"transaction_id"`
}

// CreateSignatureDevice handles the creation of a new signature device.
func (s *Server) CreateSignatureDevice(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	defer request.Body.Close()

	var req CreateSignatureRequestBody

	if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
		// More specific error handling for JSON decoding issues
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"Invalid JSON body",
			err.Error(), // Include the underlying error for debugging
		})
		return
	}

	// forward the request to the device manager to create a new device
	_, err := s.deviceManager.AddDevice(req.ID, req.Algorithm, req.Label)

	var responseBody CreateSignatureDeviceResponse
	if err != nil {
		// If an error occurs, set the error response and RETURN.
		responseBody = CreateSignatureDeviceResponse{
			Status: "error",
			Error:  err.Error(),
		}
		WriteAPIResponse(response, http.StatusBadRequest, responseBody) // Use 400 or specific error status
		return                                                          // Crucial: Stop execution here
	}

	// If no error, set the success response.
	responseBody = CreateSignatureDeviceResponse{
		Status: "success",
		Error:  "", // Error field remains empty on success
	}

	// Send the success response.
	WriteAPIResponse(response, http.StatusOK, responseBody)
}

func (s *Server) SignTransaction(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	defer request.Body.Close()

	var req SignTransactionRequestBody
	if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
		http.Error(response, "Bad request: Invalid JSON body", http.StatusBadRequest)
		return
	}

	deviceId := req.ID
	data := req.Transaction
	if deviceId == "" || data == "" {
		http.Error(response, "Bad request: Missing device ID or data", http.StatusBadRequest)
		return
	}

	// Look for the previously created device in the device manager
	device, err := s.deviceManager.GetDevice(deviceId)
	if err != nil {
		WriteAPIResponse(response, http.StatusNotFound, SignTransactionResponse{
			Error: err.Error(),
		})
		return
	}

	// Ask the actual device to sign the transaction
	signature, signedData, err := device.SignTransaction(data)
	if err != nil {
		WriteAPIResponse(response, http.StatusInternalServerError, SignTransactionResponse{
			Error: err.Error(),
		})
		return
	}

	WriteAPIResponse(response, http.StatusOK, SignTransactionResponse{
		Signature:  signature,
		SignedData: signedData,
	})
}

func (s *Server) ListTransactions(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	defer request.Body.Close()

	var req ListTransactionsRequestBody
	if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
		http.Error(response, "Bad request: Invalid JSON body", http.StatusBadRequest)
		return
	}

	deviceId := req.ID
	if deviceId == "" {
		http.Error(response, "Bad request: Missing device ID", http.StatusBadRequest)
		return
	}

	// Look for the previously created device in the device manager
	device, err := s.deviceManager.GetDevice(deviceId)
	if err != nil {
		WriteAPIResponse(response, http.StatusNotFound, SignTransactionResponse{
			Error: err.Error(),
		})
		return
	}

	// Get the list of transactions from the device
	transactions := device.ListTransactions()

	// Transform the transactions into a slice of SignTransactionResponse
	trasactionResponses := make([]SignTransactionResponse, len(transactions), len(transactions))

	for index, t := range transactions {
		trasactionResponses[index] = SignTransactionResponse{
			Signature:  t.Signature,
			SignedData: t.Data,
			Error:      "",
		}
	}

	WriteAPIResponse(response, http.StatusOK, ListTransactionsResponse{
		Transactions: trasactionResponses,
	})
}

func (s *Server) GetTransaction(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	defer request.Body.Close()

	var req GetTransactionRequestBody
	if err := json.NewDecoder(request.Body).Decode(&req); err != nil {
		http.Error(response, "Bad request: Invalid JSON body", http.StatusBadRequest)
		return
	}

	deviceId := req.DeviceID
	// transaction_id represent the counter value for the transaction
	transactionId := req.TransactionID
	if deviceId == "" || transactionId == "" {
		http.Error(response, "Bad request: Missing device ID or transaction ID", http.StatusBadRequest)
		return
	}

	// Look for the previously created device in the device manager
	device, err := s.deviceManager.GetDevice(deviceId)
	if err != nil {
		WriteAPIResponse(response, http.StatusNotFound, SignTransactionResponse{
			Error: err.Error(),
		})
		return
	}

	id, err := strconv.ParseInt(transactionId, 10, 64)

	if err != nil {
		WriteAPIResponse(response, http.StatusNotFound, SignTransactionResponse{
			Error: err.Error(),
		})
		return
	}

	// Get the transaction from the device
	transaction, err := device.GetTransaction(int64(id))

	if err != nil {
		WriteAPIResponse(response, http.StatusNotFound, SignTransactionResponse{
			Error: err.Error(),
		})
		return
	}

	trasactionResponse := SignTransactionResponse{
		Signature:  transaction.Signature,
		SignedData: transaction.Data,
		Error:      "",
	}

	WriteAPIResponse(response, http.StatusOK, trasactionResponse)
}
