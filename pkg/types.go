package pkg

import (
	"github.com/gbrlsnchs/jwt/v3"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"time"
)

type SessionId string
type ContractFormat string
type ValidationResult string

const (
	Irma    ContractFormat   = "irma"
	Valid   ValidationResult = "VALID"
	Invalid ValidationResult = "INVALID"
)

type CreateSessionRequest struct {
	Type     Type
	Version  Version
	Language Language
	// ValidFrom describes the time from which this contract should be considered valid
	ValidFrom time.Time
	// ValidFrom describes the time until this contract should be considered valid
	ValidTo time.Time
	// TemplateAttributes is an object containing extra template values. example: {"reason":"providing care"}
	TemplateAttributes map[string]string
}

// CreateSessionResult contains the results needed to setup an irma flow
type CreateSessionResult struct {
	QrCodeInfo irma.Qr
	SessionId  string
}

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

type ValidationRequest struct {
	// ContractFormat specifies the type of format used for the contract, e.g. 'irma'
	ContractFormat string

	// The actual contract in string format to validate
	ContractString string

	// ActingPartyCN is the common name of the Acting party extracted from the client cert
	ActingPartyCN string
}

type ValidationResultResponse struct {
	// ValidationResult contains a base64 encoded string of the contract.

	ValidationResult string
	// DisclosedAttributes contains an object the proven personal attributes of the user. example: { "pbdf.nuts.nuts-agb.agb-code": "00000007" }

	DisclosedAttributes []*irma.DisclosedAttribute
}
