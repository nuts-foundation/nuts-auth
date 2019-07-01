package pkg

import (
	"encoding/base64"
	"github.com/gbrlsnchs/jwt/v3"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

// DefaultValidator validates contracts using the irma logic.
type DefaultValidator struct {
	IrmaServer *irmaserver.Server
}

var hs256 = jwt.NewHMAC(jwt.SHA256, []byte("nuts"))

// ValidateContract is the entrypoint for contract validation.
// It decodes the base64 encoded contract, parses the contract string, and validates the contract.
// Returns nil, ErrUnknownContractFormat if the contract used in the message is unknown
func (v DefaultValidator) ValidateContract(b64EncodedContract string, format ContractFormat, actingPartyCN string) (*ValidationResult, error) {
	if format == IrmaFormat {
		contract, err := base64.StdEncoding.DecodeString(b64EncodedContract)
		if err != nil {
			return nil, xerrors.Errorf("could not base64-decode contract: %w", err)
		}
		signedContract, err := ParseIrmaContract(string(contract))
		if err != nil {
			return nil, err
		}

		return signedContract.Validate(actingPartyCN)
	}
	return nil, ErrUnknownContractFormat
}

// ValidateJwt validates a JWT formatted contract.
func (v DefaultValidator) ValidateJwt(token string, actingPartyCN string) (*ValidationResult, error) {
	raw, err := jwt.Parse([]byte(token))
	if err != nil {
		logrus.Error("could not parse jwt", err)
		return nil, err
	}

	if err := raw.Verify(hs256); err != nil {
		logrus.Error("could not verify jwt", err)
		return nil, err
	}

	var (
		payload nutsJwt
	)

	if _, err := raw.Decode(&payload); err != nil {
		logrus.Error("Could not decode jwt payload", err)
		return nil, err
	}

	if payload.Issuer != "nuts" {
		logrus.Error("Jwt does not has the `nuts` issuer")
		return nil, err
	}

	return payload.Contract.Validate(actingPartyCN)
}

// SessionStatus returns the current status of a certain session.
// It returns nil if the session is not found
func (v DefaultValidator) SessionStatus(id SessionID) *SessionStatusResult {
	if result := v.IrmaServer.GetSessionResult(string(id)); result != nil {
		var token string
		if result.Signature != nil {
			token, _ = createJwt(&SignedIrmaContract{*result.Signature})
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

func createJwt(contract *SignedIrmaContract) (string, error) {
	header := jwt.Header{}
	payload := nutsJwt{
		Payload: jwt.Payload{
			Issuer: "nuts",
		},
		Contract: *contract,
	}
	token, err := jwt.Sign(header, payload, hs256)
	if err != nil {
		logrus.WithError(err).Error("could not sign jwt")
		return "", nil
	}
	return string(token), nil
}

// StartSession starts an irma session.
// This is mainly a wrapper around the irma.IrmaServer.StartSession
func (v DefaultValidator) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return v.IrmaServer.StartSession(request, handler)
}
