package auth

import (
	"encoding/base64"
	"github.com/go-errors/errors"
	authIrma "github.com/nuts-foundation/nuts-proxy/auth/irma"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
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
		*authIrma.GetIrmaServer().GetSessionResult(string(id)),
	}
}

func (v DefaultValidator) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return authIrma.GetIrmaServer().StartSession(request, handler)
}
