package auth

import (
	"github.com/gbrlsnchs/jwt/v3"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

type SessionId string
type ContractFormat string
type ValidationResult string

const (
	Irma    ContractFormat   = "irma"
	Valid   ValidationResult = "VALID"
	Invalid ValidationResult = "INVALID"
)

type ContractValidator interface {
	ValidateContract(contract string, format ContractFormat, actingPartyCN string) (*ValidationResponse, error)
	ValidateJwt(contract string, actingPartyCN string) (*ValidationResponse, error)
}

type ContractSessionHandler interface {
	SessionStatus(SessionId) *SessionStatusResult
	StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error)
}

type ValidationResponse struct {
	ValidationResult    ValidationResult  `json:"validation_result"`
	ContractFormat      ContractFormat    `json:"contract_format"`
	DisclosedAttributes map[string]string `json:"disclosed_attributes"`
}

type SessionStatusResult struct {
	server.SessionResult
	NutsAuthToken string `json:"nuts_auth_token"`
}

type NutsJwt struct {
	jwt.Payload
	Contract SignedIrmaContract `json:"nuts_signature"`
}
