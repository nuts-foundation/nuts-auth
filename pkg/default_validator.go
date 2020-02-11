package pkg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/nuts-foundation/nuts-registry/pkg/db"

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
	irmaConfig *irma.Configuration
	registry   registry.RegistryClient
	crypto     nutscrypto.Client
}

// IsInitialized is a helper function to determine if the validator has been initialized properly.
func (v DefaultValidator) IsInitialized() bool {
	return v.irmaConfig != nil
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
		return signedContract.Validate(actingPartyCN, v.irmaConfig)
	}
	return nil, ErrUnknownContractFormat
}

// ErrInvalidContract is returned when the JWT or included signature is not up to spec
var ErrInvalidContract = errors.New("invalid contract")

// ValidateJwt validates a JWT formatted contract.
func (v DefaultValidator) ValidateJwt(token string, actingPartyCN string) (*ContractValidationResult, error) {
	parsedToken, err := jwt.Parse(token, func(token *jwt.Token) (i interface{}, e error) {
		legalEntity := token.Claims.(jwt.MapClaims)["sub"]
		if legalEntity == nil || legalEntity == "" {
			return nil, ErrLegalEntityNotFound
		}

		// get public key
		org, err := v.registry.OrganizationById(legalEntity.(string))
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

	if parsedToken.Claims.(jwt.MapClaims)["iss"] != "nuts" {
		return nil, fmt.Errorf("jwt does not have the nuts issuer: %w", ErrInvalidContract)
	}

	payload, err := convertClaimsToPayload(parsedToken.Claims.(jwt.MapClaims))
	if err != nil {
		return nil, err
	}

	return payload.Contract.Validate(actingPartyCN, v.irmaConfig)
}

// SessionStatus returns the current status of a certain session.
// It returns nil if the session is not found
func (v DefaultValidator) SessionStatus(id SessionID) (*SessionStatusResult, error) {
	if result := v.IrmaServer.GetSessionResult(string(id)); result != nil {
		var token string
		if result.Signature != nil {
			sic := SignedIrmaContract{*result.Signature}
			le, err := v.legalEntityFromContract(sic)
			if err != nil {
				return nil, fmt.Errorf("could not create JWT for given session: %w", err)
			}

			token, _ = v.createJwt(&sic, le)
		}
		result := &SessionStatusResult{*result, token}
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

	le, err := v.registry.ReverseLookup(params["legal_entity"])
	if err != nil {
		return "", err
	}

	return string(le.Identifier), nil
}

type nutsJwt struct {
	jwt.StandardClaims
	Contract SignedIrmaContract `json:"nuts_signature"`
}

// createJwt from a signed irma contract. Returns a JWT signed with the provided legalEntity.
func (v DefaultValidator) createJwt(contract *SignedIrmaContract, legalEntity string) (string, error) {
	payload := nutsJwt{
		StandardClaims: jwt.StandardClaims{
			Issuer:  "nuts",
			Subject: legalEntity,
		},
		Contract: *contract,
	}

	claims, err := convertPayloadToClaims(payload)
	if err != nil {
		err = fmt.Errorf("could not construct claims: %w", err)
		logrus.Error(err)
		return "", err
	}

	tokenString, err := v.crypto.SignJwtFor(claims, types.LegalEntity{URI: legalEntity})
	if err != nil {
		err = fmt.Errorf("could not sign jwt: %w", err)
		logrus.Error(err)
		return "", err
	}
	return tokenString, nil
}

// convertPayloadToClaims converts a nutsJwt struct to a map of strings so it can be signed with the crypto module
func convertPayloadToClaims(payload nutsJwt) (map[string]interface{}, error) {

	var (
		jsonString []byte
		err        error
		claims     map[string]interface{}
	)

	if jsonString, err = json.Marshal(payload); err != nil {
		logrus.WithError(err).Error("could not sign jwt")
		return nil, fmt.Errorf("could not marshall payload: %w", err)
	}

	if err := json.Unmarshal(jsonString, &claims); err != nil {
		return nil, fmt.Errorf("could not unmarshall string: %w", err)
	}

	return claims, nil
}

func convertClaimsToPayload(claims map[string]interface{}) (*nutsJwt, error) {
	var (
		jsonString []byte
		err        error
		payload    nutsJwt
	)

	if jsonString, err = json.Marshal(claims); err != nil {
		return nil, fmt.Errorf("could not marshall payload: %w", err)
	}

	if err := json.Unmarshal(jsonString, &payload); err != nil {
		return nil, fmt.Errorf("could not unmarshall string: %w", err)
	}

	return &payload, nil
}

// StartSession starts an irma session.
// This is mainly a wrapper around the irma.IrmaServer.StartSession
func (v DefaultValidator) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return v.IrmaServer.StartSession(request, handler)
}

var ErrLegalEntityNotProvided = errors.New("legalEntity not provided")

// ParseAndValidateJwtBearerToken validates the jwt signature and returns the containing claims
func (v DefaultValidator) ParseAndValidateJwtBearerToken(acString string) (*NutsJwtClaims, error) {
	parser := &jwt.Parser{ValidMethods: []string{jwt.SigningMethodRS256.Name}}
	token, err := parser.ParseWithClaims(acString, &NutsJwtClaims{}, func(token *jwt.Token) (i interface{}, e error) {
		legalEntity := token.Claims.(*NutsJwtClaims).Issuer
		if legalEntity == "" {
			return nil, ErrLegalEntityNotProvided
		}

		// get public key
		org, err := v.registry.OrganizationById(legalEntity)
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
		if claims, ok := token.Claims.(*NutsJwtClaims); ok {
			return claims, nil
		}
	}
	return nil, err
}

// BuildAccessToken builds an access token based on the oauth claims and the identity of the user provided by the identityValidationResult
// The token gets signed with the custodians private key and returned as a string.
func (v DefaultValidator) BuildAccessToken(jwtClaims *NutsJwtClaims, identityValidationResult *ContractValidationResult) (string, error) {

	if identityValidationResult.ValidationResult != Valid {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("invalid contract"))
	}

	issuer := jwtClaims.Subject
	if issuer == "" {
		return "", fmt.Errorf("could not build accessToken: %w", errors.New("subject is missing"))
	}

	sessionClaims := map[string]interface{}{
		// Issuer: custodian issuing the JWT
		"iss": issuer,
		// AGB code of the end-user
		"sub": identityValidationResult.DisclosedAttributes["nuts.agb.agbcode"],
		// Subject (Patient) identifier (oid encoded BSN)
		"sid": jwtClaims.SubjectId,
		// ActorId
		"aid": jwtClaims.Issuer,
		//"aud": jwtClaims.Audience,
		// Expires in 15 minutes
		"exp": time.Now().Add(time.Minute * 15).Unix(),
		"iat": time.Now().Unix(),
		// TODO: include personal information when used in contract
		//"family_name": identityValidationResult.DisclosedAttributes["pbdf.gemeente.personalData.familyname"],
	}

	// Sign with the private key of the issuer
	token, err := v.crypto.SignJwtFor(sessionClaims, types.LegalEntity{URI: issuer})
	if err != nil {
		return token, fmt.Errorf("could not build accessToken: %w", err)
	}

	return token, err
}

const ssoEndpointType string = "urn:oid:1.3.6.1.4.1.54851.1:nuts-oauth-authorization-server"

func (v DefaultValidator) findTokenEndpoint(legalEntity string) (*db.Endpoint, error) {
	// TODO make this a constant in github.com/nuts-foundation/nuts-go-core
	ssoEP := ssoEndpointType
	endpoints, err := v.registry.EndpointsByOrganizationAndType(legalEntity, &ssoEP)
	if err != nil {
		return nil, fmt.Errorf("token endpoint not found: %w", err)
	}
	if len(endpoints) != 1 {
		return nil, fmt.Errorf("none or multiple registred sso endpoints found, there can only be one")
	}
	endpoint := endpoints[0]
	return &endpoint, nil
}

func (v DefaultValidator) CreateJwtBearerToken(request *CreateJwtBearerTokenRequest) (*JwtBearerAccessTokenResponse, error) {
	jti, err := uuid.NewRandom()
	if err != nil {
		return nil, err
	}

	endpoint, err := v.findTokenEndpoint(request.Custodian)
	if err != nil {
		return nil, err
	}

	claims := map[string]interface{}{
		"iss": request.Actor,
		"sub": request.Custodian,
		"sid": request.Subject,
		"aud": endpoint.Identifier,
		"usi": request.Identity,
		"exp": time.Now().Add(30 * time.Minute).Unix(),
		"iat": time.Now().Unix(),
		"jti": jti,
	}

	signingString, err := v.crypto.SignJwtFor(claims, types.LegalEntity{URI: request.Actor})
	if err != nil {
		return nil, err
	}

	return &JwtBearerAccessTokenResponse{BearerToken: signingString}, nil
}
