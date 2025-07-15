package api

import "github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"

type CreateSignatureDeviceResponse struct {
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}

func CreateSignatureDevice(id string, algorithm crypto.Algorithm, label string) CreateSignatureDeviceResponse {

}
