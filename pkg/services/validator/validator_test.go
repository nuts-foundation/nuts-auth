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

package validator

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	contractMock "github.com/nuts-foundation/nuts-auth/mock/contract"
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

		vendorID := test.VendorID("vendorName")
		request := services.CreateSessionRequest{
			Type:        contract.Type("BehandelaarLogin"),
			Language:    contract.Language("NL"),
			LegalEntity: vendorID,
		}
		ctx.registryMock.EXPECT().OrganizationById(vendorID).Return(&db.Organization{Name: "vendorName"}, nil)
		ctx.signerMock.EXPECT().StartSigningSession(gomock.Any()).Return(irmaService.SignChallenge{ID: "abc-sessionid-abc", QrCodeInfo: irma.Qr{URL: qrURL, Type: irma.ActionSigning}}, nil)

		result, err := ctx.contractService.CreateSigningSession(request)

		if !assert.NoError(t, err) {
			return
		}

		irmaResult := result.(irmaService.SignChallenge)

		assert.Equal(t, irmaResult.QrCodeInfo.URL, qrURL, "qrCode should contain the correct URL")
		assert.Equal(t, irmaResult.QrCodeInfo.Type, irma.ActionSigning, "qrCode type should be signing")
	})

	t.Run("Unknown contract returns an error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := services.CreateSessionRequest{Type: contract.Type("ShadyDeal"), Language: contract.Language("NL")}
		result, err := ctx.contractService.CreateSigningSession(request)

		assert.Nil(t, result, "result should be nil")
		assert.NotNil(t, err, "expected an error")
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
	signerMock             *contractMock.MockSigner
}

func createContext(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)
	cryptoMock := cryptoMock.NewMockClient(ctrl)
	registryMock := registryMock.NewMockRegistryClient(ctrl)
	contractValidatorMock := servicesMock.NewMockContractValidator(ctrl)
	contractSessionHandler := servicesMock.NewMockContractSessionHandler(ctrl)

	signers := map[string]contract.Signer{}
	signerMock := contractMock.NewMockSigner(ctrl)
	signers["irma"] = signerMock

	return &testContext{
		ctrl:                   ctrl,
		cryptoMock:             cryptoMock,
		registryMock:           registryMock,
		contractValidatorMock:  contractValidatorMock,
		contractSessionHandler: contractSessionHandler,
		signerMock:             signerMock,
		contractService: &service{
			config: Config{
				ActingPartyCn: "actingPartyCn",
			},
			contractSessionHandler: contractSessionHandler,
			contractValidator:      contractValidatorMock,
			crypto:                 cryptoMock,
			registry:               registryMock,
			signers:                signers,
		},
	}
}
