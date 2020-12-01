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

package irma

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/nuts-foundation/nuts-auth/logging"

	"github.com/nuts-foundation/nuts-auth/pkg/services"
	irmaserver2 "github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"

	core "github.com/nuts-foundation/nuts-go-core"

	"github.com/dgrijalva/jwt-go"
	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irma "github.com/privacybydesign/irmago"
	irmaserver "github.com/privacybydesign/irmago/server"
)

// todo rename to verifier

// VerifiablePresentationType is the irma verifiable presentation type
const VerifiablePresentationType = "IrmaVerifiablePresentation"

// ContractFormat holds the readable identifier of this signing means.
const ContractFormat = "irma"

// IrmaService validates contracts using the irma logic.
type IrmaService struct {
	IrmaSessionHandler IrmaSessionHandler
	IrmaConfig         *irma.Configuration
	IrmaServiceConfig  ValidatorConfig
	// todo: remove this when the deprecated ValidateJwt is removed
	Registry          registry.RegistryClient
	Crypto            nutscrypto.Client
	ContractTemplates contract.TemplateStore
}

type ValidatorConfig struct {
	Mode string
	// Address to bind the http server to. Default localhost:1323
	Address                   string
	PublicUrl                 string
	IrmaConfigPath            string
	IrmaSchemeManager         string
	SkipAutoUpdateIrmaSchemas bool
}

// LegacyIdentityToken is the JWT that was used as Identity token in versions prior to < 0.13
type LegacyIdentityToken struct {
	jwt.StandardClaims
	Contract SignedIrmaContract `json:"nuts_signature"`
}

// IsInitialized is a helper function to determine if the validator has been initialized properly.
func (v IrmaService) IsInitialized() bool {
	return v.IrmaConfig != nil
}

// irmaVerifiablePresentation is a specific proof for irma signatures
type irmaVerifiablePresentation struct {
	proof irmaVPProof `json:"proof"`
}

// irmaVPProof is a specific IrmaProof for the specific IrmaVerifiablePresentation
type irmaVPProof struct {
	contract.Proof
	Signature string `json:"signature"`
}

// VerifyVP expects the given raw VerifiablePresentation to be of the correct type
// todo: type check?
func (v IrmaService) VerifyVP(rawVerifiablePresentation []byte) (*contract.VerificationResult, error) {
	// Extract the Irma message
	vp := irmaVerifiablePresentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &vp); err != nil {
		return nil, err
	}

	// Create the irma contract validator
	contractValidator := contractVerifier{v.IrmaConfig, v.ContractTemplates}
	signedContract, err := contractValidator.parseSignedIrmaContract(vp.proof.Signature)
	if err != nil {
		return nil, err
	}

	cvr, err := contractValidator.verifyAll(signedContract, nil)
	if err != nil {
		return nil, err
	}

	// todo this is because of backwards compatibility
	return &contract.VerificationResult{
		State:               contract.State(cvr.ValidationResult),
		ContractFormat:      contract.Format(cvr.ContractFormat),
		DisclosedAttributes: cvr.DisclosedAttributes,
		ContractAttributes:  cvr.ContractAttributes,
	}, nil
}

// ValidateContract is the entry point for contract validation.
// It decodes the base64 encoded contract, parses the contract string, and validates the contract.
// Returns nil, ErrUnknownContractFormat if the contract used in the message is unknown
// deprecated
func (v IrmaService) ValidateContract(b64EncodedContract string, format services.ContractFormat, actingPartyCN *string) (*services.ContractValidationResult, error) {
	if format == services.IrmaFormat {
		contract, err := base64.StdEncoding.DecodeString(b64EncodedContract)
		if err != nil {
			return nil, fmt.Errorf("could not base64-decode contract: %w", err)
		}
		// Create the irma contract validator
		contractValidator := contractVerifier{v.IrmaConfig, v.ContractTemplates}
		signedContract, err := contractValidator.parseSignedIrmaContract(string(contract))
		if err != nil {
			return nil, err
		}
		return contractValidator.verifyAll(signedContract, actingPartyCN)
	}
	return nil, contract.ErrUnknownContractFormat
}

// ValidateJwt validates a JWT formatted identity token
// deprecated
func (v IrmaService) ValidateJwt(token string, actingPartyCN *string) (*services.ContractValidationResult, error) {
	parser := &jwt.Parser{ValidMethods: services.ValidJWTAlg}
	parsedToken, err := parser.ParseWithClaims(token, &services.NutsIdentityToken{}, func(token *jwt.Token) (i interface{}, e error) {
		legalEntity, err := parseTokenIssuer(token.Claims.(*services.NutsIdentityToken).Issuer)
		if err != nil {
			return nil, err
		}

		// get public key
		org, err := v.Registry.OrganizationById(legalEntity)
		if err != nil {
			return nil, err
		}

		pk, err := org.CurrentPublicKey()
		if err != nil {
			return nil, err
		}

		var key interface{}
		err = pk.Raw(&key)
		return key, err
	})

	if err != nil {
		return nil, err
	}

	claims := parsedToken.Claims.(*services.NutsIdentityToken)

	if claims.Type != services.IrmaFormat {
		return nil, fmt.Errorf("%s: %w", claims.Type, contract.ErrInvalidContractFormat)
	}

	contractStr, err := base64.StdEncoding.DecodeString(claims.Signature)
	if err != nil {
		return nil, err
	}

	// Create the irma contract validator
	contractValidator := contractVerifier{v.IrmaConfig, v.ContractTemplates}
	signedContract, err := contractValidator.parseSignedIrmaContract(string(contractStr))
	return contractValidator.verifyAll(signedContract, actingPartyCN)
}

// IrmaSessionStatus returns the current status of a certain session.
// It returns nil if the session is not found
// deprecated
func (v IrmaService) SessionStatus(id services.SessionID) (*services.SessionStatusResult, error) {
	if result := v.IrmaSessionHandler.GetSessionResult(string(id)); result != nil {
		var (
			token string
		)
		if result.Signature != nil {
			c, err := contract.ParseContractString(result.Signature.Message, v.ContractTemplates)
			sic := &SignedIrmaContract{*result.Signature, c}
			if err != nil {
				return nil, err
			}

			le, err := v.legalEntityFromContract(sic)
			if err != nil {
				return nil, fmt.Errorf("could not create JWT for given session: %w", err)
			}

			token, err = v.CreateIdentityTokenFromIrmaContract(sic, le)
			if err != nil {
				return nil, err
			}
		}
		result := &services.SessionStatusResult{SessionResult: *result, NutsAuthToken: token}
		logging.Log().Info(result.NutsAuthToken)
		return result, nil
	}
	return nil, services.ErrSessionNotFound
}

func (v IrmaService) legalEntityFromContract(sic *SignedIrmaContract) (core.PartyID, error) {
	params := sic.Contract.Params

	if _, ok := params[contract.LegalEntityAttr]; !ok {
		return core.PartyID{}, ErrLegalEntityNotProvided
	}

	le, err := v.Registry.ReverseLookup(params[contract.LegalEntityAttr])
	if err != nil {
		return core.PartyID{}, err
	}

	return le.Identifier, nil
}

// CreateIdentityTokenFromIrmaContract from a signed irma contract. Returns a JWT signed with the provided legalEntity.
func (v IrmaService) CreateIdentityTokenFromIrmaContract(contract *SignedIrmaContract, legalEntity core.PartyID) (string, error) {
	signature, err := json.Marshal(contract.IrmaContract)
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	if err != nil {
		return "", err
	}
	payload := services.NutsIdentityToken{
		StandardClaims: jwt.StandardClaims{
			Issuer: legalEntity.String(),
		},
		Signature: encodedSignature,
		Type:      services.IrmaFormat,
	}

	claims, err := convertPayloadToClaims(payload)
	if err != nil {
		return "", fmt.Errorf("could not construct claims: %w", err)
	}

	tokenString, err := v.Crypto.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: legalEntity.String()}))
	if err != nil {
		return "", fmt.Errorf("could not sign jwt: %w", err)
	}
	return tokenString, nil
}

// func for creating legacy token
func (v IrmaService) createLegacyIdentityToken(contract *SignedIrmaContract, legalEntity string) (string, error) {
	payload := LegacyIdentityToken{
		StandardClaims: jwt.StandardClaims{
			Issuer:  "nuts",
			Subject: legalEntity,
		},
		Contract: *contract,
	}

	claims, err := convertPayloadToClaimsLegacy(payload)
	if err != nil {
		err = fmt.Errorf("could not construct claims: %w", err)
		logging.Log().Error(err)
		return "", err
	}

	tokenString, err := v.Crypto.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: legalEntity}))
	if err != nil {
		err = fmt.Errorf("could not sign jwt: %w", err)
		logging.Log().Error(err)
		return "", err
	}
	return tokenString, nil
}

func convertPayloadToClaimsLegacy(payload LegacyIdentityToken) (map[string]interface{}, error) {

	var (
		jsonString []byte
		err        error
		claims     map[string]interface{}
	)

	if jsonString, err = json.Marshal(payload); err != nil {
		return nil, fmt.Errorf("could not marshall payload: %w", err)
	}

	if err := json.Unmarshal(jsonString, &claims); err != nil {
		return nil, fmt.Errorf("could not unmarshal string: %w", err)
	}

	return claims, nil
}

// convertPayloadToClaims converts a nutsJwt struct to a map of strings so it can be signed with the crypto module
func convertPayloadToClaims(payload services.NutsIdentityToken) (map[string]interface{}, error) {

	var (
		jsonString []byte
		err        error
		claims     map[string]interface{}
	)

	if jsonString, err = json.Marshal(payload); err != nil {
		return nil, fmt.Errorf("could not marshall payload: %w", err)
	}

	if err := json.Unmarshal(jsonString, &claims); err != nil {
		return nil, fmt.Errorf("could not unmarshal string: %w", err)
	}

	return claims, nil
}

// StartSession starts an irma session.
// This is mainly a wrapper around the irma.IrmaSessionHandler.StartSession
func (v IrmaService) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return v.IrmaSessionHandler.StartSession(request, handler)
}

func parseTokenIssuer(issuer string) (core.PartyID, error) {
	if issuer == "" {
		return core.PartyID{}, ErrLegalEntityNotProvided
	}
	if result, err := core.ParsePartyID(issuer); err != nil {
		return core.PartyID{}, fmt.Errorf("invalid token issuer: %w", err)
	} else {
		return result, nil
	}
}

// IrmaSessionHandler is an abstraction for the Irma Server, mainly for enabling better testing
type IrmaSessionHandler interface {
	GetSessionResult(token string) *irmaserver.SessionResult
	StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error)
}

// Compile time check if the DefaultIrmaSessionHandler implements the IrmaSessionHandler interface
var _ IrmaSessionHandler = (*DefaultIrmaSessionHandler)(nil)

// DefaultIrmaSessionHandler is a wrapper for the Irma Server
// It implements the IrmaSessionHandler interface
type DefaultIrmaSessionHandler struct {
	I *irmaserver2.Server
}

// GetSessionResult forwards to Irma Server instance
func (d *DefaultIrmaSessionHandler) GetSessionResult(token string) *irmaserver.SessionResult {
	return d.I.GetSessionResult(token)
}

// StartSession forwards to Irma Server instance
func (d *DefaultIrmaSessionHandler) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return d.I.StartSession(request, handler)
}

// ErrLegalEntityNotProvided indicates that the legalEntity is missing
var ErrLegalEntityNotProvided = errors.New("legalEntity not provided")
