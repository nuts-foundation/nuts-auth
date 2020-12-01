/*
 * Nuts auth
 * Copyright (C) 2020. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package contract

// State contains the outcome of the verification. It van be VALID or INVALID. This makes it human readable.
type State string

const (
	// Valid is used to indicate a contract was valid on the time of testing
	Valid State = "VALID"
	// Invalid is used to indicate a contract was invalid on the time of testing
	Invalid State = "INVALID"
)

// VerifierType is the type for a specific verifier
type VerifierType string

// Verifier defines the funcs needed to verify a VerifiablePresentation
type Verifier interface {
	// ValidateVP validates a verifiable presentation, it's up to the caller to select the right verifier for the given VerifiablePresentation type
	VerifyVP(rawVerifiablePresentation []byte) (*VerificationResult, error)
}

// VerifiableCredentialBase holds the basic fields for a VerifiableCredential
// todo: move or use lib
type VerifiableCredentialBase struct {
	Context      []string `json:"@context"`
	ID           *string
	Type         []string
	Issuer       *string
	IssuanceDate *string
}

// VerifiableCredentialContext is the v1 base context for VPs
// todo: move or use lib
const VerifiableCredentialContext = "https://www.w3.org/2018/credentials/v1"

// VerifiablePresentationType is used as one of the types for a VerifiablePresentation
// todo move
const VerifiablePresentationType = "VerifiablePresentation"

// VerifiablePresentation represents a W3C Verifiable Presentation
type VerifiablePresentation interface {
}

// BaseVerifiablePresentation represents a W3C Verifiable Presentation with only its Type attribute
type BaseVerifiablePresentation struct {
	Context []string               `json:"@context"`
	Proof   map[string]interface{} `json:"proof"`
	Type    []string               `json:"type"`
}

// Proof represents the Proof part of a Verifiable Presentation
// specific verifiers may extend upon this Proof
type Proof struct {
	Type string `json:"type"`
}

// Format describes the format of a signed contract. Based on the format an appropriate validator can be selected.
type Format string

// ValidationResult contains the result of a contract validation
type VerificationResult struct {
	State          State  `json:"state"`
	ContractFormat Format `json:"contract_format"`
	// DisclosedAttributes contain the attributes used to sign this contract
	DisclosedAttributes map[string]string `json:"disclosed_attributes"`
	// ContractAttributes contain the attributes used to fill the contract
	ContractAttributes map[string]string `json:"contract_attributes"`
}
