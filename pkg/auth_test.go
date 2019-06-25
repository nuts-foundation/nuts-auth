package pkg

import (
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"
	"testing"
)
type MockContractSessionHandler struct {}

const qrURL = "https://api.helder.health/auth/irmaclient/123-session-ref-123"

func (v MockContractSessionHandler) SessionStatus(SessionId) *SessionStatusResult {
	panic("implement me")
}

func (v MockContractSessionHandler) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return &irma.Qr{URL: qrURL, Type: irma.ActionSigning}, "abc-sessionid-abc", nil
}

func TestAuth_CreateContractSession(t *testing.T) {
	t.Run("Create a new session", func(t *testing.T) {
		sut := Auth{
			contractSessionHandler: MockContractSessionHandler{},
		}
		request := CreateSessionRequest{Type: Type("BehandelaarLogin"), Language: Language("NL") }
		result, err := sut.CreateContractSession(request, "Demo EHR")

		if err != nil {
			t.Error("ContractCreation failed with error:", err)
		}

		assert.Equal(t, result.QrCodeInfo.URL, qrURL, "qrCode should contain the correct URL")
		assert.Equal(t, result.QrCodeInfo.Type, irma.ActionSigning, "qrCode type should be signing")
	})

	t.Run("Unknown contract returns an error", func(t *testing.T) {
		sut := Auth{
			contractSessionHandler: MockContractSessionHandler{},
		}
		request := CreateSessionRequest{Type: Type("ShadyDeal"), Language: Language("NL") }
		result, err := sut.CreateContractSession(request, "Demo EHR")

		assert.Nil(t, result, "result should be nil")
		assert.NotNil(t, err, "expected an error")
		if !xerrors.Is(err, ErrContractNotFound) {
			t.Error("Expected error to be ErrContractNotFound")
			t.Error(err)
		}
	})
}
