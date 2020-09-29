package types

import (
	"time"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
)

// CreateSessionRequest is used to create a contract signing session.
type CreateSessionRequest struct {
	// ContractType such as "BehandelaarLogin"
	Type contract.ContractType
	// Version of the contract such as "v1"
	Version contract.Version
	// Language of the contact such as "NL"
	Language contract.Language
	// LegalEntity denotes the organization of the user
	LegalEntity string
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
	SessionID  string
}

// SessionStatusResult contains the current state of a session. If the session is DONE it also contains a JWT in the NutsAuthToken
type SessionStatusResult struct {
	server.SessionResult
	// NutsAuthToken contains the JWT if the sessionStatus is DONE
	NutsAuthToken string `json:"nuts_auth_token"`
}

// ValidationRequest is used to pass all information to ValidateContract
type ValidationRequest struct {
	// ContractFormat specifies the type of format used for the contract, e.g. 'irma'
	ContractFormat ContractFormat

	// The actual contract in string format to validate
	ContractString string

	// ActingPartyCN is the common name of the Acting party extracted from the client cert
	ActingPartyCN string
}

// CreateAccessTokenRequest contains all information to create an access token from a JwtBearerToken
type CreateAccessTokenRequest struct {
	RawJwtBearerToken string
	VendorIdentifier  string
}

// CreateJwtBearerTokenRequest contains all information to create a JwtBearerToken
type CreateJwtBearerTokenRequest struct {
	Actor         string
	Custodian     string
	IdentityToken string
	Subject       string
	Scope         string
}

// AccessTokenResponse defines the return value back to the api for the CreateAccessToken method
type AccessTokenResponse struct {
	AccessToken string
}

// JwtBearerTokenResponse defines the return value back to the api for the createJwtBearerToken method
type JwtBearerTokenResponse struct {
	BearerToken string
}
