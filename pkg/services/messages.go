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
	"crypto/x509"
	"encoding/json"

	"github.com/dgrijalva/jwt-go"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
)

// CreateSessionRequest is used to create a contract signing session.
type CreateSessionRequest struct {
	// todo correct Signing means type
	SigningMeans string
	// Message to sign
	Message string
}

// CreateSessionResult contains the results needed to setup an irma flow
type CreateSessionResult struct {
	QrCodeInfo irma.Qr
	SessionID  string
}

// SessionStatusResult contains the current state of a session. If the session is DONE it also contains a JWT in the NutsAuthToken
// deprecated
type SessionStatusResult struct {
	server.SessionResult
	// NutsAuthToken contains the JWT if the sessionStatus is DONE
	NutsAuthToken string `json:"nuts_auth_token"`
}

// ValidationRequest is used to pass all information to ValidateContract
// deprecated, moved to pkg/contract
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
	ClientCert        string
	// deprecated
	VendorIdentifier *string
}

// CreateJwtBearerTokenRequest contains all information to create a JwtBearerToken
type CreateJwtBearerTokenRequest struct {
	Actor         string
	Custodian     string
	IdentityToken *string
	Subject       *string
}

// AccessTokenResult defines the return value back to the api for the CreateAccessToken method
type AccessTokenResult struct {
	AccessToken string
}

// JwtBearerTokenResult defines the return value back to the api for the createJwtBearerToken method
type JwtBearerTokenResult struct {
	BearerToken string
}

// NutsJwtBearerToken contains the deserialized Jwt Bearer Token as defined in rfc7523. It contains a NutsIdentity token which can be
// verified by the authorization server.
type NutsJwtBearerToken struct {
	jwt.StandardClaims
	// Base64 encoded VerifiablePresentation
	UserIdentity       *string           `json:"usi"`
	SubjectID          *string           `json:"sid"`
	Scope              string            `json:"scope"`
	SigningCertificate *x509.Certificate `json:-`
}

// NutsAccessToken is a OAuth 2.0 access token which provides context to a request.
// Its contents are derived from a Jwt Bearer token. The Jwt Bearer token is verified by the authorization server and
// stripped from the proof to make it compact.
type NutsAccessToken struct {
	jwt.StandardClaims
	SubjectID  *string `json:"sid"`
	Scope      string  `json:"scope"`
	Name       string  `json:"name"`
	GivenName  string  `json:"given_name"`
	Prefix     string  `json:"prefix"`
	FamilyName string  `json:"family_name"`
	Email      string  `json:"email"`
}

// AsMap returns the claims from a NutsJwtBearerToken as a map with the json names as keys
func (token NutsJwtBearerToken) AsMap() (map[string]interface{}, error) {
	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(token)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return nil, err
	}
	return keyVals, nil
}

// ContractValidationResult contains the result of a contract validation
// deprecated, moved to pkg/contract
type ContractValidationResult struct {
	ValidationResult ValidationState `json:"validation_result"`
	ContractFormat   ContractFormat  `json:"contract_format"`
	// DisclosedAttributes contain the attributes used to sign this contract
	DisclosedAttributes map[string]string `json:"disclosed_attributes"`
	// ContractAttributes contain the attributes used to fill the contract
	ContractAttributes map[string]string `json:"contract_attributes"`
}

// TokenContainerType is used in the NutsAuthenticationTokenContainer to tell the type of the
type TokenContainerType string

// UziTokenContainerType indicate the NutsAuthenticationTokenContainer token is an Uzi signed JWT
const UziTokenContainerType TokenContainerType = "uzi"

// IrmaTokenContainerType indicate the NutsAuthenticationTokenContainer token is an irma token
const IrmaTokenContainerType TokenContainerType = "irma"

// NutsAuthenticationTokenContainer holds the base64 encoded token and a type which uniquely
// identifies the means used to sign the contract
// See the Nuts RFC002 section 6 :Authentication Token Container
// deprecated, replace with VerifiablePresentation
type NutsAuthenticationTokenContainer struct {
	// Type indicates the type of the base64 encoded Token
	Type TokenContainerType `json:"type"`
	// Token contains a base64 signed token.
	Token string `json:"token"`
}
