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

package services

import (
	"net/http"
	"time"

	core "github.com/nuts-foundation/nuts-go-core"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

// ContractValidator interface must be implemented by contract validators
// deprecated
type ContractValidator interface {
	// ValidateContract validates a signed login contract, actingPartyCN is deprecated and thus optional
	ValidateContract(contract string, format ContractFormat, actingPartyCN *string, checkTime *time.Time) (*ContractValidationResult, error)
	// ValidateJwt validates a JWT that contains a signed login contract, actingPartyCN is deprecated and thus optional
	ValidateJwt(contract string, actingPartyCN *string, checkTime *time.Time) (*ContractValidationResult, error)
	IsInitialized() bool
}

// ContractSessionHandler interface must be implemented by ContractSessionHandlers
// deprecated
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

// VPProofValueParser provides a uniform interface for Authentication services like IRMA or x509 signed tokens
type VPProofValueParser interface {
	// Parse accepts a raw ProofValue from the VP as a string. The parser tries to parse the value into a SignedToken.
	Parse(rawAuthToken string) (SignedToken, error)

	// Verify accepts a SignedToken and verifies the signature using the crypto for the specific implementation of this interface.
	Verify(token SignedToken) error
}

// ContractNotary defines the interface to draw up a contract.
type ContractNotary interface {
	// DrawUpContract draws up a contract from a template and returns a Contract which than can be signed by the user.
	DrawUpContract(template contract.Template, orgID core.PartyID, validFrom time.Time, validDuration time.Duration) (*contract.Contract, error)
	// ValidateContract checks if the contract is syntactically correct and valid at the given moment in time. It does not check the signature.
	ValidateContract(contractToValidate contract.Contract, orgID core.PartyID, checkTime time.Time) (bool, error)
}

// ContractClient defines functions for creating and validating verifiable credentials
type ContractClient interface {
	contract.VPVerifier

	// CreateSigningSession creates a signing session for the requested contract and means
	CreateSigningSession(sessionRequest CreateSessionRequest) (contract.SessionPointer, error)

	// SigningSessionStatus returns the status of the current signing session or ErrSessionNotFound is sessionID is unknown
	SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error)

	Configure() error

	// deprecated
	ContractSessionStatus(sessionID string) (*SessionStatusResult, error)
	// deprecated
	ValidateContract(request ValidationRequest) (*ContractValidationResult, error)
	// HandlerFunc returns the Irma server handler func
	// deprecated
	HandlerFunc() http.HandlerFunc
}
