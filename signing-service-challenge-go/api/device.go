package api

import (
	"encoding/json"
	"net/http"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
)

type CreateSignatureDeviceResponse struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type SignTransactionResponse struct {
	Signature  string `json:"signature"`
	Error      string `json:"error,omitempty"`
	SignedData string `json:"signed_data,omitempty"`
}

type CreateSignatureRequestBody struct {
	ID        string           `json:"id"`
	Algorithm crypto.Algorithm `json:"algorithm"` // "RSA" or "ECC"
	Label     string           `json:"label"`
}

type SignTransactionRequestBody struct {
	ID          string `json:"id"`
	Transaction string `json:"transaction"`
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

	// Assuming AddDevice returns a success indicator (ignored here via _)
	// and an error.
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
	transaction := req.Transaction
	if deviceId == "" || transaction == "" {
		http.Error(response, "Bad request: Missing device ID or transaction", http.StatusBadRequest)
		return
	}

	device, err := s.deviceManager.GetDevice(deviceId)
	if err != nil {
		WriteAPIResponse(response, http.StatusNotFound, SignTransactionResponse{
			Error: err.Error(),
		})
		return
	}

	signature, signedData, err := device.SignTransaction(transaction)
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
