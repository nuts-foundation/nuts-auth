package pkg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"
	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

// DefaultValidator validates contracts using the irma logic.
type DefaultValidator struct {
	IrmaServer IrmaServerClient
	IrmaConfig *irma.Configuration
	Registry   registry.RegistryClient
	Crypto     nutscrypto.Client
}

// LegacyIdentityToken is the JWT that was used as Identity token in versions prior to < 0.13
type LegacyIdentityToken struct {
	jwt.StandardClaims
	Contract SignedIrmaContract `json:"nuts_signature"`
}

// IsInitialized is a helper function to determine if the validator has been initialized properly.
func (v DefaultValidator) IsInitialized() bool {
	return v.IrmaConfig != nil
}

// ValidateContract is the entrypoint for contract validation.
// It decodes the base64 encoded contract, parses the contract string, and validates the contract.
// Returns nil, ErrUnknownContractFormat if the contract used in the message is unknown
func (v DefaultValidator) ValidateContract(b64EncodedContract string, format ContractFormat, actingPartyCN string) (*ContractValidationResult, error) {
	if format == IrmaFormat {
		contract, err := base64.StdEncoding.DecodeString(b64EncodedContract)
		if err != nil {
			return nil, fmt.Errorf("could not base64-decode contract: %w", err)
		}
		signedContract, err := ParseIrmaContract(string(contract))
		if err != nil {
			return nil, err
		}
		return signedContract.Validate(actingPartyCN, v.IrmaConfig)
	}
	return nil, ErrUnknownContractFormat
}

// ValidateJwt validates a JWT formatted identity token
func (v DefaultValidator) ValidateJwt(token string, actingPartyCN string) (*ContractValidationResult, error) {
	// try legacy first
	legacyResult, err := v.validateLegacyJwt(token, actingPartyCN)
	if err == nil {
		return legacyResult, nil
	}

	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Name}}
	parsedToken, err := parser.ParseWithClaims(token, &NutsIdentityToken{}, func(token *jwt.Token) (i interface{}, e error) {
		//parsedToken, err := parser.Parse(token, func(token *jwt.Token) (i interface{}, e error) {
		legalEntity := token.Claims.(*NutsIdentityToken).Issuer
		if legalEntity == "" {
			return nil, ErrLegalEntityNotFound
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

		return pk.Materialize()
	})

	if err != nil {
		return nil, err
	}

	claims := parsedToken.Claims.(*NutsIdentityToken)

	if claims.Type != IrmaFormat {
		return nil, fmt.Errorf("%s: %w", claims.Type, ErrInvalidContractFormat)
	}

	contractStr, err := base64.StdEncoding.DecodeString(claims.Signature)
	if err != nil {
		return nil, err
	}
	irmaContract := SignedIrmaContract{}

	if json.Unmarshal(contractStr, &irmaContract.IrmaContract) != nil {
		return nil, err
	}
	return irmaContract.Validate(actingPartyCN, v.IrmaConfig)
}

var ErrNotLegacyContract = errors.New("not a legacy contract")

// validateLegacyJwt validates the old style tokens
func (v DefaultValidator) validateLegacyJwt(token string, actingPartyCN string) (*ContractValidationResult, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (i interface{}, e error) {
		if token.Claims.(jwt.MapClaims)["iss"] != "nuts" {
			return nil, ErrNotLegacyContract
		}
		legalEntity := token.Claims.(jwt.MapClaims)["sub"]

		if legalEntity == nil || legalEntity == "" {
			return nil, ErrLegalEntityNotFound
		}

		// get public key
		org, err := v.Registry.OrganizationById(legalEntity.(string))
		if err != nil {
			return nil, err
		}

		pk, err := org.CurrentPublicKey()
		if err != nil {
			return nil, err
		}
		return pk.Materialize()
	})

	if err != nil {
		return nil, fmt.Errorf("could not parse jwt: %w", err)
	}

	payload, err := convertClaimsToPayload(parsedToken.Claims.(jwt.MapClaims))
	if err != nil {
		return nil, err
	}
	return payload.Contract.Validate(actingPartyCN, v.IrmaConfig)
}

func convertClaimsToPayload(claims map[string]interface{}) (*LegacyIdentityToken, error) {
	var (
		jsonString []byte
		err        error
		payload    LegacyIdentityToken
	)

	if jsonString, err = json.Marshal(claims); err != nil {
		return nil, fmt.Errorf("could not marshall payload: %w", err)
	}

	if err := json.Unmarshal(jsonString, &payload); err != nil {
		return nil, fmt.Errorf("could not unmarshall string: %w", err)
	}

	return &payload, nil
}

// SessionStatus returns the current status of a certain session.
// It returns nil if the session is not found
func (v DefaultValidator) SessionStatus(id SessionID) (*SessionStatusResult, error) {
	if result := v.IrmaServer.GetSessionResult(string(id)); result != nil {
		var (
			token       string
			legacyToken string
		)
		if result.Signature != nil {
			sic := SignedIrmaContract{*result.Signature}
			le, err := v.legalEntityFromContract(sic)
			if err != nil {
				return nil, fmt.Errorf("could not create JWT for given session: %w", err)
			}

			token, err = v.CreateIdentityTokenFromIrmaContract(&sic, le)
			if err != nil {
				return nil, err
			}
			legacyToken, err = v.createLegacyIdentityToken(&sic, le)
			if err != nil {
				return nil, err
			}
		}
		result := &SessionStatusResult{*result, token, legacyToken}
		logrus.Info(result.NutsAuthToken)
		return result, nil
	}
	return nil, ErrSessionNotFound
}

// ErrLegalEntityNotFound is returned when the legalEntity can not be found based on the contract text
var ErrLegalEntityNotFound = errors.New("missing legal entity in contract text")

func (v DefaultValidator) legalEntityFromContract(sic SignedIrmaContract) (string, error) {
	c, err := ContractFromMessageContents(sic.IrmaContract.Message)
	if err != nil {
		return "", err
	}

	params, err := c.extractParams(sic.IrmaContract.Message)
	if err != nil {
		return "", err
	}

	if _, ok := params["legal_entity"]; !ok {
		return "", ErrLegalEntityNotProvided
	}

	le, err := v.Registry.ReverseLookup(params["legal_entity"])
	if err != nil {
		return "", err
	}

	return string(le.Identifier), nil
}

// CreateIdentityTokenFromIrmaContract from a signed irma contract. Returns a JWT signed with the provided legalEntity.
func (v DefaultValidator) CreateIdentityTokenFromIrmaContract(contract *SignedIrmaContract, legalEntity string) (string, error) {
	signature, err := json.Marshal(contract.IrmaContract)
	encodedSignature := base64.StdEncoding.EncodeToString(signature)
	if err != nil {
		return "", err
	}
	payload := NutsIdentityToken{
		StandardClaims: jwt.StandardClaims{
			Issuer: legalEntity,
		},
		Signature: encodedSignature,
		Type:      IrmaFormat,
	}

	claims, err := convertPayloadToClaims(payload)
	if err != nil {
		return "", fmt.Errorf("could not construct claims: %w", err)
	}

	tokenString, err := v.Crypto.SignJwtFor(claims, types.LegalEntity{URI: legalEntity})
	if err != nil {
		return "", fmt.Errorf("could not sign jwt: %w", err)
	}
	return tokenString, nil
}

// func for creating legacy token
func (v DefaultValidator) createLegacyIdentityToken(contract *SignedIrmaContract, legalEntity string) (string, error) {
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
		logrus.Error(err)
		return "", err
	}

	tokenString, err := v.Crypto.SignJwtFor(claims, types.LegalEntity{URI: legalEntity})
	if err != nil {
		err = fmt.Errorf("could not sign jwt: %w", err)
		logrus.Error(err)
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
		return nil, fmt.Errorf("could not unmarshall string: %w", err)
	}

	return claims, nil
}

// convertPayloadToClaims converts a nutsJwt struct to a map of strings so it can be signed with the crypto module
func convertPayloadToClaims(payload NutsIdentityToken) (map[string]interface{}, error) {

	var (
		jsonString []byte
		err        error
		claims     map[string]interface{}
	)

	if jsonString, err = json.Marshal(payload); err != nil {
		return nil, fmt.Errorf("could not marshall payload: %w", err)
	}

	if err := json.Unmarshal(jsonString, &claims); err != nil {
		return nil, fmt.Errorf("could not unmarshall string: %w", err)
	}

	return claims, nil
}

// StartSession starts an irma session.
// This is mainly a wrapper around the irma.IrmaServer.StartSession
func (v DefaultValidator) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return v.IrmaServer.StartSession(request, handler)
}

// ParseAndValidateJwtBearerToken validates the jwt signature and returns the containing claims
func (v DefaultValidator) ParseAndValidateJwtBearerToken(acString string) (*NutsJwtBearerToken, error) {
	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Name}}
	token, err := parser.ParseWithClaims(acString, &NutsJwtBearerToken{}, func(token *jwt.Token) (i interface{}, e error) {
		legalEntity := token.Claims.(*NutsJwtBearerToken).Issuer
		if legalEntity == "" {
			return nil, ErrLegalEntityNotProvided
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

		return pk.Materialize()
	})

	if token != nil && token.Valid {
		if claims, ok := token.Claims.(*NutsJwtBearerToken); ok {
			return claims, nil
		}
	}

	return nil, err
}

// BuildAccessToken builds an access token based on the oauth claims and the identity of the user provided by the identityValidationResult
// The token gets signed with the custodians private key and returned as a string.
func (v DefaultValidator) BuildAccessToken(jwtBearerToken *NutsJwtBearerToken, identityValidationResult *ContractValidationResult) (string, error) {

	if identityValidationResult.ValidationResult != Valid {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("invalid contract"))
	}

	issuer := jwtBearerToken.Subject
	if issuer == "" {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("subject is missing"))
	}

	at := NutsAccessToken{
		StandardClaims: jwt.StandardClaims{
			// Expires in 15 minutes
			ExpiresAt: time.Now().Add(time.Minute * 15).Unix(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    issuer,
			Subject:   jwtBearerToken.Issuer,
		},
		SubjectID: jwtBearerToken.SubjectID,
		Scope:     jwtBearerToken.Scope,
		// based on
		// https://privacybydesign.foundation/attribute-index/en/pbdf.gemeente.personalData.html
		// https://privacybydesign.foundation/attribute-index/en/pbdf.pbdf.email.html
		// and
		// https://openid.net/specs/openid-connect-basic-1_0.html#StandardClaims
		FamilyName: identityValidationResult.DisclosedAttributes["gemeente.personalData.familyname"],
		GivenName:  identityValidationResult.DisclosedAttributes["gemeente.personalData.firstnames"],
		Prefix:     identityValidationResult.DisclosedAttributes["gemeente.personalData.prefix"],
		Name:       identityValidationResult.DisclosedAttributes["gemeente.personalData.fullname"],
		Email:      identityValidationResult.DisclosedAttributes["pbdf.email.email"],
	}

	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(at)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return "", err
	}

	// Sign with the private key of the issuer
	token, err := v.Crypto.SignJwtFor(keyVals, types.LegalEntity{URI: issuer})
	if err != nil {
		return token, fmt.Errorf("could not build accessToken: %w", err)
	}

	return token, err
}

// CreateJwtBearerToken creates a JwtBearerTokenResponse containing a jwtBearerToken from a CreateJwtBearerTokenRequest.
func (v DefaultValidator) CreateJwtBearerToken(request *CreateJwtBearerTokenRequest) (*JwtBearerTokenResponse, error) {
	jti, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	jwtBearerToken := NutsJwtBearerToken{
		StandardClaims: jwt.StandardClaims{
			//Audience:  endpoint.Identifier.String(),
			ExpiresAt: time.Now().Add(30 * time.Minute).Unix(),
			Id:        jti.String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    request.Actor,
			NotBefore: 0,
			Subject:   request.Custodian,
		},
		IdentityToken: request.IdentityToken,
		SubjectID:     request.Subject,
		Scope:         request.Scope,
	}

	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(jwtBearerToken)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return nil, err
	}

	signingString, err := v.Crypto.SignJwtFor(keyVals, types.LegalEntity{URI: request.Actor})
	if err != nil {
		return nil, err
	}

	return &JwtBearerTokenResponse{BearerToken: signingString}, nil
}

// ParseAndValidateAccessToken parses and validates a accesstoken string and returns a filled in NutsAccessToken.
func (v DefaultValidator) ParseAndValidateAccessToken(accessToken string) (*NutsAccessToken, error) {
	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Name}}
	token, err := parser.ParseWithClaims(accessToken, &NutsAccessToken{}, func(token *jwt.Token) (i interface{}, e error) {
		legalEntity := token.Claims.(*NutsAccessToken).Issuer
		if legalEntity == "" {
			return nil, ErrLegalEntityNotProvided
		}

		// Check if the care provider which signed the token is managed by this node
		if !v.Crypto.KeyExistsFor(types.LegalEntity{URI: legalEntity}) {
			return nil, fmt.Errorf("invalid token: not signed by a care provider of this node")
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

		return pk.Materialize()
	})

	if token != nil && token.Valid {
		if claims, ok := token.Claims.(*NutsAccessToken); ok {
			return claims, nil
		}
	}
	return nil, err
}
