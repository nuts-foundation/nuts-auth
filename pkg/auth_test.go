package pkg

import (
	"errors"
	"fmt"
	"testing"

	"github.com/nuts-foundation/nuts-auth/pkg/services"

	irma2 "github.com/nuts-foundation/nuts-auth/pkg/services/irma"

	registryTest "github.com/nuts-foundation/nuts-registry/test"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"

	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-go-test/io"
	registry "github.com/nuts-foundation/nuts-registry/pkg"

	"github.com/golang/mock/gomock"
	cryptoMock2 "github.com/nuts-foundation/nuts-crypto/test/mock"
	core "github.com/nuts-foundation/nuts-go-core"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	irma "github.com/privacybydesign/irmago"
	irmaservercore "github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"
)

var organizationID = registryTest.OrganizationID("00000001")
var otherOrganizationID = registryTest.OrganizationID("00000002")

type MockContractSessionHandler struct {
	SessionStatusResult *services.SessionStatusResult
}

type MockAccessTokenHandler struct {
	claims                              *services.NutsJwtBearerToken
	parseAndValidateAccessTokenJwtError error
	accessToken                         string
	accessTokenError                    error
}

func (m MockAccessTokenHandler) ParseAndValidateJwtBearerToken(acString string) (*services.NutsJwtBearerToken, error) {
	return m.claims, m.parseAndValidateAccessTokenJwtError
}

func (m MockAccessTokenHandler) BuildAccessToken(jwtClaims *services.NutsJwtBearerToken, identityValidationResult *services.ContractValidationResult) (string, error) {
	if m.accessTokenError != nil {
		return "", m.accessTokenError
	}
	if len(m.accessToken) > 0 {
		return m.accessToken, nil
	}
	return "fresh access token", nil
}

type MockContractValidator struct {
	jwtResult  services.ContractValidationResult
	irmaResult services.ContractValidationResult
}

func (m MockAccessTokenHandler) CreateJwtBearerToken(request *services.CreateJwtBearerTokenRequest) (*services.JwtBearerTokenResponse, error) {
	panic("implement me")
}

func (m MockContractValidator) IsInitialized() bool {
	return true
}

func (m MockContractValidator) ValidateContract(contract string, format services.ContractFormat, actingPartyCN string) (*services.ContractValidationResult, error) {
	return &m.irmaResult, nil
}

func (m MockContractValidator) ValidateJwt(contract string, actingPartyCN string) (*services.ContractValidationResult, error) {
	return &m.jwtResult, nil
}

const qrURL = "https://api.nuts-test.example" + irma2.IrmaMountPath + "/123-session-ref-123"

func (v MockContractSessionHandler) SessionStatus(services.SessionID) (*services.SessionStatusResult, error) {
	return v.SessionStatusResult, nil
}

func (m MockAccessTokenHandler) ParseAndValidateAccessToken(accessToken string) (*services.NutsAccessToken, error) {
	panic("implement me")
}

func (v MockContractSessionHandler) StartSession(request interface{}, handler irmaservercore.SessionHandler) (*irma.Qr, string, error) {
	return &irma.Qr{URL: qrURL, Type: irma.ActionSigning}, "abc-sessionid-abc", nil
}

func TestAuth_CreateContractSession(t *testing.T) {
	registerTestDependencies(t)
	t.Run("Create a new session", func(t *testing.T) {
		sut := Auth{
			ContractSessionHandler: MockContractSessionHandler{},
		}
		request := services.CreateSessionRequest{Type: contract.Type("BehandelaarLogin"), Language: contract.Language("NL")}
		result, err := sut.CreateContractSession(request)

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
		request := services.CreateSessionRequest{Type: contract.Type("ShadyDeal"), Language: contract.Language("NL")}
		result, err := sut.CreateContractSession(request)

		assert.Nil(t, result, "result should be nil")
		assert.NotNil(t, err, "expected an error")
		assert.True(t, errors.Is(err, contract.ErrContractNotFound), "expected ErrContractNotFound")
	})
}

func TestAuth_ContractByType(t *testing.T) {
	registerTestDependencies(t)
	sut := Auth{ValidContracts: contract.Contracts}
	t.Run("get contract by type", func(t *testing.T) {
		result, err := sut.ContractByType(contract.Type("BehandelaarLogin"), contract.Language("NL"), contract.Version("v1"))

		if !assert.Nil(t, err) || !assert.NotNil(t, result) {
			t.FailNow()
		}

		assert.Equal(t, contract.Version("v1"), result.Version)
		assert.Equal(t, contract.Language("NL"), result.Language)
		assert.Equal(t, contract.Type("BehandelaarLogin"), result.Type)
	})

	t.Run("an unknown contract returns an error", func(t *testing.T) {
		result, err := sut.ContractByType(contract.Type("UnknownContract"), contract.Language("NL"), contract.Version("v1"))

		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, contract.ErrContractNotFound), "expected ErrContractNotFound")
	})
}

func TestAuthInstance(t *testing.T) {
	registerTestDependencies(t)
	t.Run("Same instance is returned", func(t *testing.T) {
		assert.Equal(t, AuthInstance(), AuthInstance())
	})

	t.Run("default config is used", func(t *testing.T) {
		assert.Equal(t, AuthInstance().Config, DefaultAuthConfig())
	})
}

func TestAuth_Configure(t *testing.T) {
	registerTestDependencies(t)
	t.Run("ok - mode defaults to server", func(t *testing.T) {
		i := &Auth{
			Config: AuthConfig{},
		}
		_ = i.Configure()
		assert.Equal(t, core.ServerEngineMode, i.Config.Mode)
	})

	t.Run("ok - client mode", func(t *testing.T) {
		i := &Auth{
			Config: AuthConfig{
				Mode: core.ClientEngineMode,
			},
		}

		assert.NoError(t, i.Configure())
	})

	t.Run("error - missing actingPartyCn", func(t *testing.T) {
		i := &Auth{
			Config: AuthConfig{
				Mode:      core.ServerEngineMode,
				PublicUrl: "url",
			},
		}

		assert.Equal(t, ErrMissingActingParty, i.Configure())
	})

	t.Run("error - missing publicUrl", func(t *testing.T) {
		i := &Auth{
			Config: AuthConfig{
				Mode:          core.ServerEngineMode,
				ActingPartyCn: "url",
			},
		}

		assert.Equal(t, ErrMissingPublicURL, i.Configure())
	})

	t.Run("ok - config valid", func(t *testing.T) {
		i := &Auth{
			Config: AuthConfig{
				Mode:                      core.ServerEngineMode,
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

	t.Run("error - IRMA config failure", func(t *testing.T) {
		i := &Auth{
			Config: AuthConfig{
				Mode:                      core.ServerEngineMode,
				PublicUrl:                 "url",
				ActingPartyCn:             "url",
				IrmaSchemeManager:         "asdasdsad",
				SkipAutoUpdateIrmaSchemas: true,
			},
		}
		err := i.Configure()
		if !assert.NoError(t, err) {
			return
		}
	})
}

func TestAuth_ContractSessionStatus(t *testing.T) {
	registerTestDependencies(t)
	t.Run("returns err if session is not found", func(t *testing.T) {
		i := &Auth{
			ContractSessionHandler: MockContractSessionHandler{},
		}

		_, err := i.ContractSessionStatus("ID")

		assert.True(t, errors.Is(err, services.ErrSessionNotFound))
	})

	t.Run("returns session status when found", func(t *testing.T) {
		i := &Auth{
			ContractSessionHandler: MockContractSessionHandler{
				SessionStatusResult: &services.SessionStatusResult{
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
	registerTestDependencies(t)
	t.Run("Returns error on unknown constract type", func(t *testing.T) {
		i := &Auth{
			ContractValidator: MockContractValidator{},
		}

		_, err := i.ValidateContract(services.ValidationRequest{ContractFormat: "Unknown"})

		assert.True(t, errors.Is(err, contract.ErrUnknownContractFormat))
	})

	t.Run("Returns validation result for JWT", func(t *testing.T) {
		i := &Auth{
			ContractValidator: MockContractValidator{
				jwtResult: services.ContractValidationResult{
					ValidationResult: services.Valid,
				},
			},
		}

		result, err := i.ValidateContract(services.ValidationRequest{ContractFormat: services.JwtFormat})

		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, services.Valid, result.ValidationResult)
	})

	t.Run("Returns validation result for Irma", func(t *testing.T) {
		i := &Auth{
			ContractValidator: MockContractValidator{
				irmaResult: services.ContractValidationResult{
					ValidationResult: services.Valid,
				},
			},
		}

		result, err := i.ValidateContract(services.ValidationRequest{ContractFormat: services.IrmaFormat})

		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, services.Valid, result.ValidationResult)
	})
}

func TestAuth_CreateAccessToken(t *testing.T) {
	registerTestDependencies(t)
	t.Run("invalid jwt", func(t *testing.T) {
		i := &Auth{AccessTokenHandler: MockAccessTokenHandler{claims: nil, parseAndValidateAccessTokenJwtError: fmt.Errorf("validationError")}}
		response, err := i.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "jwt bearer token validation failed")
		}
	})

	t.Run("invalid identity", func(t *testing.T) {
		i := &Auth{
			AccessTokenHandler: MockAccessTokenHandler{claims: &services.NutsJwtBearerToken{}},
			ContractValidator: MockContractValidator{
				jwtResult: services.ContractValidationResult{ValidationResult: services.Invalid},
			},
		}
		response, err := i.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "identity validation failed")
		}
	})

	t.Run("it creates a token", func(t *testing.T) {
		expectedAT := "ac"
		i := &Auth{
			ContractValidator: MockContractValidator{
				jwtResult: services.ContractValidationResult{ValidationResult: services.Valid, DisclosedAttributes: map[string]string{"name": "Henk de Vries"}},
			},
			AccessTokenHandler: MockAccessTokenHandler{claims: &services.NutsJwtBearerToken{}, accessToken: expectedAT},
		}

		response, err := i.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})
		assert.Nil(t, err)
		if assert.NotNil(t, response) {
			assert.Equal(t, expectedAT, response.AccessToken)
		}
	})
}

func TestAuth_KeyExistsFor(t *testing.T) {
	registerTestDependencies(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cryptoMock := cryptoMock2.NewMockClient(ctrl)
	auth := &Auth{
		Crypto: cryptoMock,
	}

	t.Run("false when crypto returns false", func(t *testing.T) {
		cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(false)

		orgID := auth.KeyExistsFor(organizationID)
		assert.False(t, orgID)
	})

	t.Run("true when crypto returns false", func(t *testing.T) {
		cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(true)

		assert.True(t, auth.KeyExistsFor(organizationID))
	})
}

func TestAuth_OrganizationNameById(t *testing.T) {
	registerTestDependencies(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	registryMock := registryMock.NewMockRegistryClient(ctrl)
	auth := &Auth{
		Registry: registryMock,
	}

	t.Run("returns name", func(t *testing.T) {
		registryMock.EXPECT().OrganizationById(organizationID).Return(&db.Organization{Name: "name"}, nil)

		name, err := auth.OrganizationNameByID(organizationID)
		if assert.NoError(t, err) {
			assert.Equal(t, "name", name)
		}
	})

	t.Run("returns error", func(t *testing.T) {
		registryMock.EXPECT().OrganizationById(gomock.Any()).Return(nil, errors.New("error"))

		_, err := auth.OrganizationNameByID(organizationID)
		assert.Error(t, err)
	})
}

func registerTestDependencies(t *testing.T) {
	// This makes sure instances of Auth use test instances of Crypto and Registry which write their data to a temp dir
	testDirectory := io.TestDirectory(t)
	crypto.NewTestCryptoInstance(testDirectory)
	registry.NewTestRegistryInstance(testDirectory)
}
