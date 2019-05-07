package auth

import (
	"github.com/nuts-foundation/nuts-auth/auth"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
)

// ContractSigningRequest contains all information needed to start a session
type ContractSigningRequest struct {
	auth.ContractSigningRequest
}

// CreateSessionResult contains the results needed to setup an irma flow
type CreateSessionResult struct {
	QrCodeInfo irma.Qr `json:"qr_code_info"`
	SessionId  string  `json:"session_id"`
}

// SessionStatusResult describes the current status of the session
type SessionStatusResult struct {
	server.SessionResult
}

type ValidationRequest struct {
	// ContractFormat specifies the type of format used for the contract, e.g. 'irma'
	ContractFormat string `json:"contract_format"`

	// The actual contract in string format to validate
	ContractString string `json:"contract_string"`

	// ActingPartyCN is the common name of the Acting party extracted from the client cert
	ActingPartyCN string `json:"acting_party_cn"`
}

type ValidationResultResponse struct {
	// ValidationResult contains a base64 encoded string of the contract.

	ValidationResult string `json:"validation_result"`
	// DisclosedAttributes contains an object the proven personal attributes of the user. example: { "pbdf.nuts.nuts-agb.agb-code": "00000007" }

	DisclosedAttributes []*irma.DisclosedAttribute `json:"disclosed_attributes"`
}
