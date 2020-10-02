package services

import (
	"github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
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

// AccessTokenHandler interface must be implemented by Access token handlers. It defines the interface to handle all
// logic concerning creating and introspecting OAuth 2.0 Access tokens
type AccessTokenHandler interface {
	// CreateJwtBearerToken from a JwtBearerTokenRequest. Returns a signed JWT string.
	CreateJwtBearerToken(request *CreateJwtBearerTokenRequest) (token *JwtBearerTokenResult, err error)

	// ParseAndValidateJwtBearerToken accepts a jwt encoded bearer token as string and returns the NutsJwtBearerToken object if valid.
	// it returns a ErrLegalEntityNotProvided if the issuer does not contain an legal entity
	// it returns a ErrOrganizationNotFound if the organization in the issuer could not be found in the registry
	ParseAndValidateJwtBearerToken(token string) (*NutsJwtBearerToken, error)

	// BuildAccessToken create a jwt encoded access token from a NutsJwtBearerToken and a ContractValidationResult.
	BuildAccessToken(jwtClaims *NutsJwtBearerToken, identityValidationResult *ContractValidationResult) (token string, err error)

	// ParseAndValidateAccessToken parses and validates an AccessToken and returns a filled NutsAccessToken as result.
	// it returns a ErrLegalEntityNotProvided if the issuer does not contain an legal entity
	// it returns a ErrOrganizationNotFound if the organization in the issuer could not be found in the registry
	ParseAndValidateAccessToken(accessToken string) (*NutsAccessToken, error)
}
