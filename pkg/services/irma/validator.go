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
	"time"

	"github.com/nuts-foundation/nuts-auth/logging"

	irmaserver2 "github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/nuts-foundation/nuts-auth/pkg/services"

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
const VerifiablePresentationType = contract.VPType("NutsIrmaPresentation")

// ContractFormat holds the readable identifier of this signing means.
const ContractFormat = contract.SigningMeans("irma")

// Service validates contracts using the IRMA logic.
type Service struct {
	IrmaSessionHandler SessionHandler
	IrmaConfig         *irma.Configuration
	IrmaServiceConfig  ValidatorConfig
	// todo: remove this when the deprecated ValidateJwt is removed
	Registry          registry.RegistryClient
	Crypto            nutscrypto.Client
	ContractTemplates contract.TemplateStore
}

// ValidatorConfig holds the configuration for the irma validator.
type ValidatorConfig struct {
	// Address to bind the http server to. Default localhost:1323
	Address string
	// PublicURL is used for discovery for the IRMA app.
	PublicURL string
	// Where to find the IrmaConfig files including the schemas
	IrmaConfigPath string
	// Which scheme manager to use
	IrmaSchemeManager string
	// Auto update the schemas every x minutes or not?
	SkipAutoUpdateIrmaSchemas bool
}

// IsInitialized is a helper function to determine if the validator has been initialized properly.
func (v Service) IsInitialized() bool {
	return v.IrmaConfig != nil
}

// VerifiablePresentation is a specific proof for irma signatures
type VerifiablePresentation struct {
	contract.VerifiablePresentationBase
	Proof VPProof `json:"proof"`
}

// VPProof is a specific IrmaProof for the specific VerifiablePresentation
type VPProof struct {
	contract.Proof
	ProofValue string `json:"proofValue"`
}

// VerifyVP expects the given raw VerifiablePresentation to be of the correct type
// todo: type check?
func (v Service) VerifyVP(rawVerifiablePresentation []byte, checkTime *time.Time) (*contract.VPVerificationResult, error) {
	// Extract the Irma message
	vp := VerifiablePresentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &vp); err != nil {
		return nil, fmt.Errorf("could not verify VP: %w", err)
	}

	// Create the irma contract validator
	contractValidator := contractVerifier{v.IrmaConfig, v.ContractTemplates}
	signedContract, err := contractValidator.Parse(vp.Proof.ProofValue)
	if err != nil {
		return nil, err
	}

	cvr, err := contractValidator.verifyAll(signedContract.(*SignedIrmaContract), nil, checkTime)
	if err != nil {
		return nil, err
	}

	signerAttributes, err := signedContract.SignerAttributes()
	if err != nil {
		return nil, fmt.Errorf("could not verify vp: could not get signer attributes: %w", err)
	}

	return &contract.VPVerificationResult{
		Validity:            contract.State(cvr.ValidationResult),
		VPType:              contract.VPType(cvr.ContractFormat),
		DisclosedAttributes: signerAttributes,
		ContractAttributes:  signedContract.Contract().Params,
	}, nil
}

// ValidateContract is the entry point for contract validation.
// It decodes the base64 encoded contract, parses the contract string, and validates the contract.
// Returns nil, ErrUnknownContractFormat if the contract used in the message is unknown
// deprecated
func (v Service) ValidateContract(b64EncodedContract string, format services.ContractFormat, actingPartyCN *string, checkTime *time.Time) (*services.ContractValidationResult, error) {
	if format == services.IrmaFormat {
		contract, err := base64.StdEncoding.DecodeString(b64EncodedContract)
		if err != nil {
			return nil, fmt.Errorf("could not base64-decode contract: %w", err)
		}
		// Create the irma contract validator
		contractValidator := contractVerifier{v.IrmaConfig, v.ContractTemplates}
		signedContract, err := contractValidator.ParseIrmaContract(contract)
		if err != nil {
			return nil, err
		}
		return contractValidator.verifyAll(signedContract.(*SignedIrmaContract), actingPartyCN, checkTime)
	}
	return nil, contract.ErrUnknownContractFormat
}

// ValidateJwt validates a JWT formatted identity token
// deprecated
func (v Service) ValidateJwt(rawJwt string, actingPartyCN *string, checkTime *time.Time) (*services.ContractValidationResult, error) {
	parser := &jwt.Parser{ValidMethods: services.ValidJWTAlg}
	parsedToken, err := parser.ParseWithClaims(rawJwt, &services.NutsIdentityToken{}, func(token *jwt.Token) (i interface{}, e error) {
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
	signedContract, err := contractValidator.ParseIrmaContract(contractStr)
	if err != nil {
		return nil, err
	}
	return contractValidator.verifyAll(signedContract.(*SignedIrmaContract), actingPartyCN, checkTime)
}

// SessionStatus returns the current status of a certain session.
// It returns nil if the session is not found
// deprecated
func (v Service) SessionStatus(id services.SessionID) (*services.SessionStatusResult, error) {
	if result := v.IrmaSessionHandler.GetSessionResult(string(id)); result != nil {
		var (
			token string
		)
		if result.Signature != nil {
			c, err := contract.ParseContractString(result.Signature.Message, v.ContractTemplates)
			sic := &SignedIrmaContract{
				IrmaContract: *result.Signature,
				contract:     c,
			}
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

func (v Service) legalEntityFromContract(sic *SignedIrmaContract) (core.PartyID, error) {
	params := sic.contract.Params

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
func (v Service) CreateIdentityTokenFromIrmaContract(contract *SignedIrmaContract, legalEntity core.PartyID) (string, error) {
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
// This is mainly a wrapper around the irma.SessionHandler.StartSession
func (v Service) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return v.IrmaSessionHandler.StartSession(request, handler)
}

func parseTokenIssuer(issuer string) (core.PartyID, error) {
	if issuer == "" {
		return core.PartyID{}, ErrLegalEntityNotProvided
	}
	result, err := core.ParsePartyID(issuer)
	if err != nil {
		return core.PartyID{}, fmt.Errorf("invalid token issuer: %w", err)
	}
	return result, nil
}

// SessionHandler is an abstraction for the Irma Server, mainly for enabling better testing
type SessionHandler interface {
	GetSessionResult(token string) *irmaserver.SessionResult
	StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error)
}

// Compile time check if the DefaultIrmaSessionHandler implements the SessionHandler interface
var _ SessionHandler = (*DefaultIrmaSessionHandler)(nil)

// DefaultIrmaSessionHandler is a wrapper for the Irma Server
// It implements the SessionHandler interface
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
