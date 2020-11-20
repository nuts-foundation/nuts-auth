package services

import (
	"net/http"

	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

// ContractValidator interface must be implemented by contract validators
type ContractValidator interface {
	// ValidateContract validates a signed login contract, actingPartyCN is deprecated and thus optional
	ValidateContract(contract string, format ContractFormat, actingPartyCN *string) (*ContractValidationResult, error)
	// ValidateJwt validates a JWT that contains a signed login contract, actingPartyCN is deprecated and thus optional
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

// AuthenticationTokenContainerEncoder defines the interface for Authentication Token Containers services
type AuthenticationTokenContainerEncoder interface {
	// Decode accepts a raw token container encoded as a string and decodes it into a NutsAuthenticationTokenContainer
	Decode(rawTokenContainer string) (*NutsAuthenticationTokenContainer, error)

	// Encode accepts a NutsAuthenticationTokenContainer and encodes in into a string
	Encode(authTokenContainer NutsAuthenticationTokenContainer) (string, error)
}

// SignedToken defines the uniform interface to crypto specific implementations such as Irma or x509 tokens.
type SignedToken interface {
	// SignerAttributes extracts a map of attribute names and their values from the signature
	SignerAttributes() (map[string]string, error)
	// Contract extracts the Contract from the SignedToken
	Contract() contract.Contract
}

// AuthenticationTokenParser provides a uniform interface for Authentication services like IRMA or x509 signed tokens
type AuthenticationTokenParser interface {
	// Parse accepts a raw Auth token string. The parser tries to parse the token into a SignedToken.
	Parse(rawAuthToken string) (SignedToken, error)

	// Verify accepts a SignedToken and verifies the signature using the crypto for the specific implementation of this interface.
	Verify(token SignedToken) error
}

// ContractClient defines functions for creating and validating signed contracts
type ContractClient interface {
	CreateContractSession(sessionRequest CreateSessionRequest) (*CreateSessionResult, error)
	ContractSessionStatus(sessionID string) (*SessionStatusResult, error)
	ValidateContract(request ValidationRequest) (*ContractValidationResult, error)
	Configure() error
	ContractValidatorInstance() ContractValidator
	// HandlerFunc returns the Irma server handler func
	HandlerFunc() http.HandlerFunc
}
