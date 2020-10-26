package services

import (
	"net/http"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	core "github.com/nuts-foundation/nuts-go-core"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
)

// ContractValidator interface must be implemented by contract validators
type ContractValidator interface {
	// actingPartyCN is deprecated and thus optional
	ValidateContract(contract string, format ContractFormat, actingPartyCN *string) (*ContractValidationResult, error)
	// actingPartyCN is deprecated and thus optional
	ValidateJwt(contract string, actingPartyCN *string) (*ContractValidationResult, error)
	IsInitialized() bool
}

// ContractSessionHandler interface must be implemented by ContractSessionHandlers
type ContractSessionHandler interface {
	SessionStatus(session SessionID) (*SessionStatusResult, error)
	StartSession(request interface{}, handler server.SessionHandler) (*irma.Qr, string, error)
}

// OAuthClient is the client interface for the OAuth service
type OAuthClient interface {
	CreateAccessToken(request CreateAccessTokenRequest) (*AccessTokenResult, error)
	CreateJwtBearerToken(request CreateJwtBearerTokenRequest) (*JwtBearerTokenResult, error)
	IntrospectAccessToken(token string) (*NutsAccessToken, error)
	Configure() error
}

// ContractClient defines functions for creating and validating signed contracts
type ContractClient interface {
	CreateContractSession(sessionRequest CreateSessionRequest) (*CreateSessionResult, error)
	ContractSessionStatus(sessionID string) (*SessionStatusResult, error)
	ContractByType(contractType contract.Type, language contract.Language, version contract.Version) (*contract.Template, error)
	ValidateContract(request ValidationRequest) (*ContractValidationResult, error)
	KeyExistsFor(legalEntity core.PartyID) bool
	OrganizationNameByID(legalEntity core.PartyID) (string, error)
	Configure() error
	ContractValidatorInstance() ContractValidator
	// HandlerFunc returns the Irma server handler func
	HandlerFunc() http.HandlerFunc
}
