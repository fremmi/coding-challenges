package domain

import "github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"

// TODO: signature device domain model ...
type Device struct {
	id    string
	label string

	generator crypto.Generator
}
