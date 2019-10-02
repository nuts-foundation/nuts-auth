package pkg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gbrlsnchs/jwt/v3"
	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

// DefaultValidator validates contracts using the irma logic.
type DefaultValidator struct {
	IrmaServer *irmaserver.Server
	registry   registry.RegistryClient
	crypto     nutscrypto.Client
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

		return signedContract.Validate(actingPartyCN)
	}
	return nil, ErrUnknownContractFormat
}

// ErrInvalidContract is returned when the JWT or included signature is not up to spec
var ErrInvalidContract = errors.New("invalid contract")

// ValidateJwt validates a JWT formatted contract.
func (v DefaultValidator) ValidateJwt(token string, actingPartyCN string) (*ValidationResult, error) {
	var payload nutsJwt

	_, err := jwt.Verify([]byte(token), jwt.None(), &payload)
	if err != nil {
		return nil, fmt.Errorf("could not parse jwt: %w", ErrInvalidContract)
	}

	if payload.Issuer != "nuts" {
		return nil, fmt.Errorf("jwt does not have the nuts issuer: %w", ErrInvalidContract)
	}

	if len(payload.Subject) == 0 {
		return nil, fmt.Errorf("jwt does not have a subject: %w", ErrInvalidContract)
	}

	// find the public key
	org, err := v.registry.OrganizationById(payload.Subject)
	if err != nil {
		return nil, fmt.Errorf("could not verify jwt: %w", err)
	}

	if org.PublicKey == nil {
		return nil, fmt.Errorf("could not verify jwt: missing public key for %s", org.Identifier)
	}

	pub, err := nutscrypto.PemToPublicKey([]byte(*org.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("could not verify jwt: %w", err)
	}

	verifier := jwt.NewRS256(jwt.RSAPublicKey(pub))

	if _, err := jwt.Verify([]byte(token), verifier, &payload); err != nil {
		return nil, fmt.Errorf("could not verify jwt: %w", err)
	}

	return payload.Contract.Validate(actingPartyCN)
}

// SessionStatus returns the current status of a certain session.
// It returns nil if the session is not found
func (v DefaultValidator) SessionStatus(id SessionID, legalEntity string) *SessionStatusResult {
	if result := v.IrmaServer.GetSessionResult(string(id)); result != nil {
		var token string
		if result.Signature != nil {
			token, _ = v.createJwt(&SignedIrmaContract{*result.Signature}, legalEntity)
		}
		result :=  &SessionStatusResult{*result, token}
		logrus.Info(result.NutsAuthToken)
		return result
	}
	return nil
}

type nutsJwt struct {
	jwt.Payload
	Contract SignedIrmaContract `json:"nuts_signature"`
}

func (v DefaultValidator) createJwt(contract *SignedIrmaContract, legalEntity string) (string, error) {
	payload := nutsJwt{
		Payload: jwt.Payload{
			Issuer: "nuts",
			Subject: legalEntity,
		},
		Contract: *contract,
	}

	// todo ugly?
	var claims map[string]interface{}
	jsonString, _ := json.Marshal(payload)
	json.Unmarshal(jsonString, &claims)
	tokenString, err := v.crypto.SignJwtFor(claims, types.LegalEntity{URI: legalEntity})

	if err != nil {
		logrus.WithError(err).Error("could not sign jwt")
		return "", err
	}
	return tokenString, nil
}

// StartSession starts an irma session.
// This is mainly a wrapper around the irma.IrmaServer.StartSession
func (v DefaultValidator) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return v.IrmaServer.StartSession(request, handler)
}
