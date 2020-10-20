/*
 * Nuts auth
 * Copyright (C) 2020. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package contract

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	servicesMock "github.com/nuts-foundation/nuts-auth/mock/services"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	irmaService "github.com/nuts-foundation/nuts-auth/pkg/services/irma"
	cryptoMock "github.com/nuts-foundation/nuts-crypto/test/mock"
	core "github.com/nuts-foundation/nuts-go-core"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"github.com/nuts-foundation/nuts-registry/test"
	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"
)

const qrURL = "https://api.nuts-test.example" + irmaService.IrmaMountPath + "/123-session-ref-123"

func TestService_CreateContractSession(t *testing.T) {
	t.Run("Create a new session", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := services.CreateSessionRequest{
			Type:        contract.Type("BehandelaarLogin"),
			Language:    contract.Language("NL"),
			LegalEntity: "vendorName",
		}
		ctx.contractSessionHandler.EXPECT().StartSession(gomock.Any(), gomock.Any()).Return(&irma.Qr{URL: qrURL, Type: irma.ActionSigning}, "abc-sessionid-abc", nil)

		result, err := ctx.contractService.CreateContractSession(request)

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, result.QrCodeInfo.URL, qrURL, "qrCode should contain the correct URL")
		assert.Equal(t, result.QrCodeInfo.Type, irma.ActionSigning, "qrCode type should be signing")
	})

	t.Run("Unknown contract returns an error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := services.CreateSessionRequest{Type: contract.Type("ShadyDeal"), Language: contract.Language("NL")}
		result, err := ctx.contractService.CreateContractSession(request)

		assert.Nil(t, result, "result should be nil")
		assert.NotNil(t, err, "expected an error")
		assert.True(t, errors.Is(err, contract.ErrContractNotFound), "expected ErrContractNotFound")
	})
}

func TestService_ContractByType(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("get contract by type", func(t *testing.T) {
		result, err := ctx.contractService.ContractByType("BehandelaarLogin", "NL", "v1")

		if !assert.Nil(t, err) || !assert.NotNil(t, result) {
			return
		}

		assert.Equal(t, contract.Version("v1"), result.Version)
		assert.Equal(t, contract.Language("NL"), result.Language)
		assert.Equal(t, contract.Type("BehandelaarLogin"), result.Type)
	})

	t.Run("an unknown contract returns an error", func(t *testing.T) {
		result, err := ctx.contractService.ContractByType("UnknownContract", "NL", "v1")

		assert.Nil(t, result)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, contract.ErrContractNotFound), "expected ErrContractNotFound")
	})
}

func TestService_ContractSessionStatus(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("returns err if session is not found", func(t *testing.T) {
		ctx.contractSessionHandler.EXPECT().SessionStatus(services.SessionID("ID")).Return(nil, services.ErrSessionNotFound)

		_, err := ctx.contractService.ContractSessionStatus("ID")

		assert.True(t, errors.Is(err, services.ErrSessionNotFound))
	})

	t.Run("returns session status when found", func(t *testing.T) {
		ctx.contractSessionHandler.EXPECT().SessionStatus(services.SessionID("ID")).Return(&services.SessionStatusResult{NutsAuthToken: "token"}, nil)

		result, err := ctx.contractService.ContractSessionStatus("ID")

		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, "token", result.NutsAuthToken)
	})
}

func TestService_ValidateContract(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("Returns error on unknown constract type", func(t *testing.T) {
		_, err := ctx.contractService.ValidateContract(services.ValidationRequest{ContractFormat: "Unknown"})

		assert.True(t, errors.Is(err, contract.ErrUnknownContractFormat))
	})

	t.Run("Returns validation result for JWT", func(t *testing.T) {
		ctx.contractValidatorMock.EXPECT().ValidateJwt(gomock.Any(), gomock.Any()).Return(&services.ContractValidationResult{
			ValidationResult: services.Valid,
		}, nil)

		result, err := ctx.contractService.ValidateContract(services.ValidationRequest{ContractFormat: services.JwtFormat})

		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, services.Valid, result.ValidationResult)
	})

	t.Run("Returns validation result for Irma", func(t *testing.T) {
		ctx.contractValidatorMock.EXPECT().ValidateContract(gomock.Any(), gomock.Any(), gomock.Any()).Return(&services.ContractValidationResult{
			ValidationResult: services.Valid,
		}, nil)

		result, err := ctx.contractService.ValidateContract(services.ValidationRequest{ContractFormat: services.IrmaFormat})

		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, services.Valid, result.ValidationResult)
	})
}

func TestService_KeyExistsFor(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("false when nutsCrypto returns false", func(t *testing.T) {
		ctx.cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(false)

		orgID := ctx.contractService.KeyExistsFor(organizationID)
		assert.False(t, orgID)
	})

	t.Run("true when nutsCrypto returns false", func(t *testing.T) {
		ctx.cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(true)

		assert.True(t, ctx.contractService.KeyExistsFor(organizationID))
	})
}

func TestService_OrganizationNameById(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("returns name", func(t *testing.T) {
		ctx.registryMock.EXPECT().OrganizationById(organizationID).Return(&db.Organization{Name: "name"}, nil)

		name, err := ctx.contractService.OrganizationNameByID(organizationID)
		if assert.NoError(t, err) {
			assert.Equal(t, "name", name)
		}
	})

	t.Run("returns error", func(t *testing.T) {
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(nil, errors.New("error"))

		_, err := ctx.contractService.OrganizationNameByID(organizationID)
		assert.Error(t, err)
	})
}

func TestContract_Configure(t *testing.T) {
	t.Run("ok - config valid", func(t *testing.T) {
		c := service{
			config: Config{
				Mode:                      core.ServerEngineMode,
				PublicUrl:                 "url",
				ActingPartyCn:             "url",
				IrmaConfigPath:            "../../../testdata/irma",
				SkipAutoUpdateIrmaSchemas: true,
			},
		}

		if assert.NoError(t, c.Configure()) {
			// BUG: nuts-auth#23
			assert.True(t, c.contractValidator.IsInitialized())
		}
	})
}

var organizationID = test.OrganizationID("00000001")

type testContext struct {
	ctrl                   *gomock.Controller
	cryptoMock             *cryptoMock.MockClient
	registryMock           *registryMock.MockRegistryClient
	contractValidatorMock  *servicesMock.MockContractValidator
	contractSessionHandler *servicesMock.MockContractSessionHandler
	contractService        *service
}

func createContext(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)
	cryptoMock := cryptoMock.NewMockClient(ctrl)
	registryMock := registryMock.NewMockRegistryClient(ctrl)
	contractValidatorMock := servicesMock.NewMockContractValidator(ctrl)
	contractSessionHandler := servicesMock.NewMockContractSessionHandler(ctrl)
	return &testContext{
		ctrl:                   ctrl,
		cryptoMock:             cryptoMock,
		registryMock:           registryMock,
		contractValidatorMock:  contractValidatorMock,
		contractSessionHandler: contractSessionHandler,
		contractService: &service{
			config: Config{
				ActingPartyCn: "actingPartyCn",
			},
			contractSessionHandler: contractSessionHandler,
			contractValidator:      contractValidatorMock,
			contractTemplates:      contract.StandardContractTemplates,
			crypto:                 cryptoMock,
			registry:               registryMock,
		},
	}
}
