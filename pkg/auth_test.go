package pkg

import (
	"testing"

	"errors"

	"github.com/golang/mock/gomock"
	cryptoMock2 "github.com/nuts-foundation/nuts-crypto/mock"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/stretchr/testify/assert"
)

type MockContractSessionHandler struct {
	SessionStatusResult *SessionStatusResult
}

type MockContractValidator struct {
	jwtResult  ValidationResult
	irmaResult ValidationResult
}

func (m MockContractValidator) IsInitialized() bool {
	return true
}

func (m MockContractValidator) ValidateContract(contract string, format ContractFormat, actingPartyCN string) (*ValidationResult, error) {
	return &m.irmaResult, nil
}

func (m MockContractValidator) ValidateJwt(contract string, actingPartyCN string) (*ValidationResult, error) {
	return &m.jwtResult, nil
}

const qrURL = "https://api.helder.health/auth/irmaclient/123-session-ref-123"

func (v MockContractSessionHandler) SessionStatus(SessionID) (*SessionStatusResult, error) {
	return v.SessionStatusResult, nil
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

func TestAuthInstance(t *testing.T) {
	t.Run("Same instance is returned", func(t *testing.T) {
		assert.Equal(t, AuthInstance(), AuthInstance())
	})

	t.Run("default config is used", func(t *testing.T) {
		assert.Equal(t, AuthInstance().Config, AuthConfig{})
	})
}

func TestAuth_Configure(t *testing.T) {
	t.Run("Configure returns error on missing actingPartyCn", func(t *testing.T) {
		i := &Auth{
			Config: AuthConfig{
				PublicUrl: "url",
			},
		}

		assert.Equal(t, ErrMissingActingParty, i.Configure())
	})

	t.Run("Configure returns error on missing publicUrl", func(t *testing.T) {
		i := &Auth{
			Config: AuthConfig{
				ActingPartyCn: "url",
			},
		}

		assert.Equal(t, ErrMissingPublicURL, i.Configure())
	})

	t.Run("Configure returns no error on valid config", func(t *testing.T) {
		i := &Auth{
			Config: AuthConfig{
				PublicUrl:                 "url",
				ActingPartyCn:             "url",
				IrmaConfigPath:            "../testdata/irma",
				SkipAutoUpdateIrmaSchemas: true,
			},
		}

		if assert.NoError(t, i.Configure()) {
			// BUG: nuts-auth#23
			assert.True(t, i.ContractValidator.IsInitialized())
		}
	})
}

func TestAuth_ContractSessionStatus(t *testing.T) {
	t.Run("returns err if session is not found", func(t *testing.T) {
		i := &Auth{
			ContractSessionHandler: MockContractSessionHandler{},
		}

		_, err := i.ContractSessionStatus("ID")

		assert.True(t, errors.Is(err, ErrSessionNotFound))
	})

	t.Run("returns session status when found", func(t *testing.T) {
		i := &Auth{
			ContractSessionHandler: MockContractSessionHandler{
				SessionStatusResult: &SessionStatusResult{
					NutsAuthToken: "token",
				},
			},
		}

		result, err := i.ContractSessionStatus("ID")

		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "token", result.NutsAuthToken)
	})
}

func TestAuth_ValidateContract(t *testing.T) {
	t.Run("Returns error on unknown constract type", func(t *testing.T) {
		i := &Auth{
			ContractValidator: MockContractValidator{},
		}

		_, err := i.ValidateContract(ValidationRequest{ContractFormat: "Unknown"})

		assert.True(t, errors.Is(err, ErrUnknownContractFormat))
	})

	t.Run("Returns validation result for JWT", func(t *testing.T) {
		i := &Auth{
			ContractValidator: MockContractValidator{
				jwtResult: ValidationResult{
					ValidationResult: Valid,
				},
			},
		}

		result, err := i.ValidateContract(ValidationRequest{ContractFormat: JwtFormat})

		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, Valid, result.ValidationResult)
	})

	t.Run("Returns validation result for Irma", func(t *testing.T) {
		i := &Auth{
			ContractValidator: MockContractValidator{
				irmaResult: ValidationResult{
					ValidationResult: Valid,
				},
			},
		}

		result, err := i.ValidateContract(ValidationRequest{ContractFormat: IrmaFormat})

		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, Valid, result.ValidationResult)
	})
}

func TestAuth_KeyExistsFor(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cryptoMock := cryptoMock2.NewMockClient(ctrl)
	auth := &Auth{
		cryptoClient: cryptoMock,
	}

	t.Run("false when crypto returns false", func(t *testing.T) {
		cryptoMock.EXPECT().KeyExistsFor(gomock.Any()).Return(false)

		assert.False(t, auth.KeyExistsFor(""))
	})

	t.Run("true when crypto returns false", func(t *testing.T) {
		cryptoMock.EXPECT().KeyExistsFor(gomock.Any()).Return(true)

		assert.True(t, auth.KeyExistsFor(""))
	})
}

func TestAuth_OrganizationNameById(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	registryMock := registryMock.NewMockRegistryClient(ctrl)
	auth := &Auth{
		registryClient: registryMock,
	}

	t.Run("returns name", func(t *testing.T) {
		registryMock.EXPECT().OrganizationById("").Return(&db.Organization{Name: "name"}, nil)

		name, err := auth.OrganizationNameByID("")
		if assert.NoError(t, err) {
			assert.Equal(t, "name", name)
		}
	})

	t.Run("returns error", func(t *testing.T) {
		registryMock.EXPECT().OrganizationById(gomock.Any()).Return(nil, errors.New("error"))

		_, err := auth.OrganizationNameByID("")
		assert.Error(t, err)
	})
}
