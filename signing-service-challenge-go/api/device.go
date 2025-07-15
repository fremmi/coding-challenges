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

type SingTransactionRequestBody struct {
	ID          string `json:"id"`
	Transaction string `json:"transaction"`
}

func (s *Server) CreateSignatureDevice(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	body, err := request.GetBody()
	if err != nil {
		WriteInternalError(response)
		return
	}

	var req CreateSignatureRequestBody
	if err = json.NewDecoder(body).Decode(req); err != nil {
		http.Error(response, "Bad request: Invalid JSON body", http.StatusBadRequest)
		return
	}

	defer request.Body.Close()

	_, err = s.deviceManager.AddDevice(req.ID, req.Algorithm, req.Label)

	var responseBody CreateSignatureDeviceResponse
	if err != nil {
		// Handle error (e.g., device already exists)
		responseBody = CreateSignatureDeviceResponse{
			Status: "error",
			Error:  err.Error(),
		}
	}

	responseBody = CreateSignatureDeviceResponse{
		Status: "success",
		Error:  "",
	}

	WriteAPIResponse(response, http.StatusOK, responseBody)
}

func (s *Server) SignTransaction(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		WriteErrorResponse(response, http.StatusMethodNotAllowed, []string{
			http.StatusText(http.StatusMethodNotAllowed),
		})
		return
	}

	body, err := request.GetBody()
	if err != nil {
		WriteInternalError(response)
		return
	}

	var req SingTransactionRequestBody
	if err = json.NewDecoder(body).Decode(&req); err != nil {
		http.Error(response, "Bad request: Invalid JSON body", http.StatusBadRequest)
		return
	}

	defer request.Body.Close()
	deviceId := req.ID
	transaction := req.Transaction
	if deviceId == "" || transaction == "" {
		http.Error(response, "Bad request: Missing device ID or transaction", http.StatusBadRequest)
		return
	}

	var responseBody SignTransactionResponse
	// Retrieve the device from the device manager
	device, err := s.deviceManager.GetDevice(deviceId)
	if err != nil {
		responseBody = SignTransactionResponse{
			Error: err.Error(),
		}
	}

	signature, signed_data, err := device.SignTransaction(transaction)
	if err != nil {
		responseBody = SignTransactionResponse{
			Error: err.Error(),
		}
	}

	responseBody = SignTransactionResponse{
		Signature:  signature,
		SignedData: signed_data,
		Error:      "",
	}

	WriteAPIResponse(response, http.StatusOK, responseBody)
}
