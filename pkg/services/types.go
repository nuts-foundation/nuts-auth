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
	"errors"

	"github.com/dgrijalva/jwt-go"
)

const (
	// IrmaFormat is used to indicate a contract is in he form of a base64 encoded IRMA signature
	IrmaFormat ContractFormat = "irma"
	// JwtFormat is used to indicate a contract in in the form of a Jwt encoded signature
	JwtFormat ContractFormat = "JWT"
	// Valid is used to indicate a contract was valid on the time of testing
	Valid ValidationState = "VALID"
	// Invalid is used to indicate a contract was invalid on the time of testing
	Invalid ValidationState = "INVALID"
)

// NutsIdentityToken contains the signed identity of the user performing the request
// Deprecated
type NutsIdentityToken struct {
	jwt.StandardClaims
	//Identifier of the legalEntity who issued and signed the token
	//Issuer string
	// What kind of signature? Currently only IRMA is supported
	Type ContractFormat `json:"type"`
	// The base64 encoded signature
	Signature string `json:"sig"`
}

// ErrSessionNotFound is returned when there is no contract signing session found for a certain SessionID
var ErrSessionNotFound = errors.New("session not found")

// SessionID contains a number to uniquely identify a contract signing session
type SessionID string

// ValidationState contains the outcome of the validation. It van be VALID or INVALID. This makes it human readable.
type ValidationState string

// ContractFormat describes the format of a signed contract. Based on the format an appropriate validator can be selected.
type ContractFormat string

// ValidJWTAlg defines JWT signing algorithms allowed
var ValidJWTAlg = []string{
	jwt.SigningMethodPS256.Name,
	jwt.SigningMethodPS384.Name,
	jwt.SigningMethodPS512.Name,
	jwt.SigningMethodES256.Name,
	jwt.SigningMethodES384.Name,
	jwt.SigningMethodES512.Name,
}

// OAuthEndpointType defines the type identifier for oauth endpoints (RFCtodo)
const OAuthEndpointType = "oauth"
