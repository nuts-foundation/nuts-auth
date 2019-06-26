package pkg

import (
	"encoding/base64"
	"github.com/gbrlsnchs/jwt/v3"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"golang.org/x/xerrors"
)

type DefaultValidator struct {
	IrmaServer *irmaserver.Server
}

var hs256 = jwt.NewHMAC(jwt.SHA256, []byte("nuts"))

func (v DefaultValidator) ValidateContract(b64EncodedContract string, format ContractFormat, actingPartyCN string) (*ValidationResponse, error) {
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

func (v DefaultValidator) ValidateJwt(token string, actingPartyCN string) (*ValidationResponse, error) {
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
		payload NutsJwt
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

func (v DefaultValidator) SessionStatus(id SessionId) *SessionStatusResult {
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

func createJwt(contract *SignedIrmaContract) (string, error) {
	header := jwt.Header{}
	payload := NutsJwt{
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

func (v DefaultValidator) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return v.IrmaServer.StartSession(request, handler)
}
