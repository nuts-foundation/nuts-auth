package pkg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"

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
func (v DefaultValidator) ValidateContract(b64EncodedContract string, format ContractFormat, actingPartyCN string) (*ValidationResult, error) {
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
func (v DefaultValidator) ValidateJwt(token string, actingPartyCN string) (*ValidationResult, error) {
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
		return "", ErrLegalEntityNotFound
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
