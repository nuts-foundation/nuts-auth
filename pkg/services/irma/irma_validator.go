package irma

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nuts-foundation/nuts-auth/pkg/services"

	irmaserver2 "github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"

	core "github.com/nuts-foundation/nuts-go-core"

	"github.com/google/uuid"

	"github.com/dgrijalva/jwt-go"
	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irma "github.com/privacybydesign/irmago"
	irmaserver "github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

// IrmaMethod validates contracts using the irma logic.
type IrmaMethod struct {
	IrmaSessionHandler IrmaSessionHandler
	IrmaConfig         *irma.Configuration
	Registry           registry.RegistryClient
	Crypto             nutscrypto.Client
	ValidContracts     contract.Matrix
}

type IrmaServiceConfig struct {
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
func (v IrmaMethod) IsInitialized() bool {
	return v.IrmaConfig != nil
}

// ValidateContract is the entry point for contract validation.
// It decodes the base64 encoded contract, parses the contract string, and validates the contract.
// Returns nil, ErrUnknownContractFormat if the contract used in the message is unknown
func (v IrmaMethod) ValidateContract(b64EncodedContract string, format services.ContractFormat, actingPartyCN string) (*services.ContractValidationResult, error) {
	if format == services.IrmaFormat {
		contract, err := base64.StdEncoding.DecodeString(b64EncodedContract)
		if err != nil {
			return nil, fmt.Errorf("could not base64-decode contract: %w", err)
		}
		// Create the irma contract validator
		contractValidator := IrmaContractVerifier{v.IrmaConfig, v.ValidContracts}
		signedContract, err := contractValidator.ParseSignedIrmaContract(string(contract))
		if err != nil {
			return nil, err
		}
		return contractValidator.VerifyAll(signedContract, actingPartyCN)
	}
	return nil, contract.ErrUnknownContractFormat
}

// ValidateJwt validates a JWT formatted identity token
func (v IrmaMethod) ValidateJwt(token string, actingPartyCN string) (*services.ContractValidationResult, error) {
	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Name}}
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

		return pk.Materialize()
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
	contractValidator := IrmaContractVerifier{v.IrmaConfig, v.ValidContracts}
	signedContract, err := contractValidator.ParseSignedIrmaContract(string(contractStr))
	return contractValidator.VerifyAll(signedContract, actingPartyCN)
}

// SessionStatus returns the current status of a certain session.
// It returns nil if the session is not found
func (v IrmaMethod) SessionStatus(id services.SessionID) (*services.SessionStatusResult, error) {
	if result := v.IrmaSessionHandler.GetSessionResult(string(id)); result != nil {
		var (
			token string
		)
		if result.Signature != nil {
			contractTemplate, err := contract.NewFromMessageContents(result.Signature.Message, v.ValidContracts)
			sic := &SignedIrmaContract{*result.Signature, contractTemplate}
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
		result := &services.SessionStatusResult{*result, token}
		logrus.Info(result.NutsAuthToken)
		return result, nil
	}
	return nil, services.ErrSessionNotFound
}

func (v IrmaMethod) legalEntityFromContract(sic *SignedIrmaContract) (core.PartyID, error) {
	params, err := sic.ContractTemplate.ExtractParams(sic.IrmaContract.Message)
	if err != nil {
		return core.PartyID{}, err
	}

	if _, ok := params["legal_entity"]; !ok {
		return core.PartyID{}, ErrLegalEntityNotProvided
	}

	le, err := v.Registry.ReverseLookup(params["legal_entity"])
	if err != nil {
		return core.PartyID{}, err
	}

	return le.Identifier, nil
}

// CreateIdentityTokenFromIrmaContract from a signed irma contract. Returns a JWT signed with the provided legalEntity.
func (v IrmaMethod) CreateIdentityTokenFromIrmaContract(contract *SignedIrmaContract, legalEntity core.PartyID) (string, error) {
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
func (v IrmaMethod) createLegacyIdentityToken(contract *SignedIrmaContract, legalEntity string) (string, error) {
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

	tokenString, err := v.Crypto.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: legalEntity}))
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
		return nil, fmt.Errorf("could not unmarshall string: %w", err)
	}

	return claims, nil
}

// StartSession starts an irma session.
// This is mainly a wrapper around the irma.IrmaSessionHandler.StartSession
func (v IrmaMethod) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return v.IrmaSessionHandler.StartSession(request, handler)
}

// ParseAndValidateJwtBearerToken validates the jwt signature and returns the containing claims
func (v IrmaMethod) ParseAndValidateJwtBearerToken(acString string) (*services.NutsJwtBearerToken, error) {
	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Name}}
	token, err := parser.ParseWithClaims(acString, &services.NutsJwtBearerToken{}, func(token *jwt.Token) (i interface{}, e error) {
		legalEntity, err := parseTokenIssuer(token.Claims.(*services.NutsJwtBearerToken).Issuer)
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

		return pk.Materialize()
	})

	if token != nil && token.Valid {
		if claims, ok := token.Claims.(*services.NutsJwtBearerToken); ok {
			return claims, nil
		}
	}

	return nil, err
}

// BuildAccessToken builds an access token based on the oauth claims and the identity of the user provided by the identityValidationResult
// The token gets signed with the custodians private key and returned as a string.
func (v IrmaMethod) BuildAccessToken(jwtBearerToken *services.NutsJwtBearerToken, identityValidationResult *services.ContractValidationResult) (string, error) {

	if identityValidationResult.ValidationResult != services.Valid {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("invalid contract"))
	}

	issuer := jwtBearerToken.Subject
	if issuer == "" {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("subject is missing"))
	}

	at := services.NutsAccessToken{
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
	token, err := v.Crypto.SignJWT(keyVals, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: issuer}))
	if err != nil {
		return token, fmt.Errorf("could not build accessToken: %w", err)
	}

	return token, err
}

// CreateJwtBearerToken creates a JwtBearerTokenResult containing a jwtBearerToken from a CreateJwtBearerTokenRequest.
func (v IrmaMethod) CreateJwtBearerToken(request *services.CreateJwtBearerTokenRequest) (*services.JwtBearerTokenResult, error) {
	jti, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	jwtBearerToken := services.NutsJwtBearerToken{
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

	signingString, err := v.Crypto.SignJWT(keyVals, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: request.Actor}))
	if err != nil {
		return nil, err
	}

	return &services.JwtBearerTokenResult{BearerToken: signingString}, nil
}

// ParseAndValidateAccessToken parses and validates a accesstoken string and returns a filled in NutsAccessToken.
func (v IrmaMethod) ParseAndValidateAccessToken(accessToken string) (*services.NutsAccessToken, error) {
	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Name}}
	token, err := parser.ParseWithClaims(accessToken, &services.NutsAccessToken{}, func(token *jwt.Token) (i interface{}, e error) {
		legalEntity, err := parseTokenIssuer(token.Claims.(*services.NutsAccessToken).Issuer)
		if err != nil {
			return nil, err
		}

		// Check if the care provider which signed the token is managed by this node
		if !v.Crypto.PrivateKeyExists(cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: legalEntity.String()})) {
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
		if claims, ok := token.Claims.(*services.NutsAccessToken); ok {
			return claims, nil
		}
	}
	return nil, err
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
