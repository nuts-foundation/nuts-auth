package auth

import (
	"encoding/base64"
	"github.com/go-errors/errors"
	"github.com/nuts-foundation/nuts-proxy/auth/irma"
	irma2 "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

type ContractFormat string
type ValidationResult string

const (
	Irma    ContractFormat   = "irma"
	Valid   ValidationResult = "VALID"
	Invalid ValidationResult = "INVALID"
)

type DefaultValidator struct{}

func (v DefaultValidator) ValidateContract(b64EncodedContract string, format ContractFormat, actingPartyCN string) (*ValidationResponse, error) {
	if format == Irma {
		contract, err := base64.StdEncoding.DecodeString(b64EncodedContract)
		if err != nil {
			logrus.Error("Could not base64 decode contract_string")
			return nil, err
		}
		signedContract, err := ParseIrmaContract(string(contract))
		if err != nil {
			return nil, err
		}

		return signedContract.Validate(actingPartyCN)
	}
	return nil, errors.New("Unknown contract format. Currently supported formats: irma")
}

func (v DefaultValidator) SessionStatus(id SessionId) *SessionStatusResult {
	return &SessionStatusResult{
		*irma.GetIrmaServer().GetSessionResult(string(id)),
	}
}

func (v DefaultValidator) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma2.Qr, string, error) {
	return irma.GetIrmaServer().StartSession(request, handler)
}
