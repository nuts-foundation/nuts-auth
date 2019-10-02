package pkg

import (
	"testing"

	"errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/stretchr/testify/assert"
)

type MockContractSessionHandler struct{}

const qrURL = "https://api.helder.health/auth/irmaclient/123-session-ref-123"

func (v MockContractSessionHandler) SessionStatus(SessionID, string) *SessionStatusResult {
	panic("implement me")
}

func (v MockContractSessionHandler) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma.Qr, string, error) {
	return &irma.Qr{URL: qrURL, Type: irma.ActionSigning}, "abc-sessionid-abc", nil
}

func TestAuth_CreateContractSession(t *testing.T) {
	t.Run("Create a new session", func(t *testing.T) {
		sut := Auth{
			ContractSessionHandler: MockContractSessionHandler{},
		}
		request := CreateSessionRequest{Type: ContractType("BehandelaarLogin"), Language: Language("NL")}
		result, err := sut.CreateContractSession(request, "Demo EHR")

		if err != nil {
			t.Error("ContractCreation failed with error:", err)
		}

		assert.Equal(t, result.QrCodeInfo.URL, qrURL, "qrCode should contain the correct URL")
		assert.Equal(t, result.QrCodeInfo.Type, irma.ActionSigning, "qrCode type should be signing")
	})

	t.Run("Unknown contract returns an error", func(t *testing.T) {
		sut := Auth{
			ContractSessionHandler: MockContractSessionHandler{},
		}
		request := CreateSessionRequest{Type: ContractType("ShadyDeal"), Language: Language("NL")}
		result, err := sut.CreateContractSession(request, "Demo EHR")

		assert.Nil(t, result, "result should be nil")
		assert.NotNil(t, err, "expected an error")
		assert.True(t, errors.Is(err, ErrContractNotFound), "expected ErrContractNotFound")
	})
}

func TestAuth_ContractByType(t *testing.T) {
	t.Run("get contract by type", func(t *testing.T) {
		sut := Auth{}
		result, err := sut.ContractByType(ContractType("BehandelaarLogin"), Language("NL"), Version("v1"))

		assert.Nil(t, err)
		assert.NotNil(t, result)

		assert.Equal(t, Version("v1"), result.Version)
		assert.Equal(t, Language("NL"), result.Language)
		assert.Equal(t, ContractType("BehandelaarLogin"), result.Type)
	})

	t.Run("an unknown contract returns an error", func(t *testing.T) {
		sut := Auth{}
		result, err := sut.ContractByType(ContractType("UnknownContract"), Language("NL"), Version("v1"))

		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrContractNotFound), "expected ErrContractNotFound")
	})
}
