package auth

import (
	"encoding/base64"
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

type DefaultValidator struct {
	IrmaServer *irmaserver.Server
}

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
	if result := v.IrmaServer.GetSessionResult(string(id)); result != nil {
		return &SessionStatusResult{*result}
	}
	return nil
}

func (v DefaultValidator) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return v.IrmaServer.StartSession(request, handler)
}
