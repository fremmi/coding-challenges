package api

type CreateSignatureDeviceResponse struct {
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}

func CreateSignatureDevice(id string, algorithm Algorithm, label string) CreateSignatureDeviceResponse {

}
