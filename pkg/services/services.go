package services

import (
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"

	contract "github.com/nuts-foundation/nuts-auth/pkg/contract"
)

// ContractValidator interface must be implemented by contract validators
type ContractValidator interface {
	ValidateContract(contract string, format ContractFormat, actingPartyCN string) (*ContractValidationResult, error)
	ValidateJwt(contract string, actingPartyCN string) (*ContractValidationResult, error)
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

// AuthenticationTokenContainerService defines the interface for Authentication Token Containers services
type AuthenticationTokenContainerService interface {
	// Decodes a base64 encoded Authentication Token and returns a NutsAuthenticationTokenContainer
	DecodeAuthenticationTokenContainer(rawTokenContainer string) (*NutsAuthenticationTokenContainer, error)

	// Encodes NutsAuthenticationTokenContainer to a base64 encoded token which can be used as a usi field
	EncodeAuthenticationTokenContainer(authTokenContainer *NutsAuthenticationTokenContainer) (string, error)
}

type SignedToken interface {
	SignerAttributes() map[string]string
	Contract() contract.Contract
}

// AuthenticationTokenService provides a uniform interface for Authentication services like IRMA or x509 signed tokens
type AuthenticationTokenService interface {
	// Parse a raw Auth token string. The token must be of the same type as the implementing service
	Parse(rawAuthToken string) (SignedToken, error)

	// Verify the signature of the SignedToken using the crypto of the Authentication service
	Verify(token SignedToken) error

	// Encode the token to base64
	Encode(token SignedToken) (string, error)
}
