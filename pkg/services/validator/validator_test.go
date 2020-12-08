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
	"encoding/json"
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	cryptoMock "github.com/nuts-foundation/nuts-crypto/test/mock"
	core "github.com/nuts-foundation/nuts-go-core"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"

	contractMock "github.com/nuts-foundation/nuts-auth/mock/contract"
	servicesMock "github.com/nuts-foundation/nuts-auth/mock/services"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	irmaService "github.com/nuts-foundation/nuts-auth/pkg/services/irma"
)

const qrURL = "https://api.nuts-test.example" + irmaService.IrmaMountPath + "/123-session-ref-123"

func TestService_CreateContractSession(t *testing.T) {
	t.Run("Create a new session", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := services.CreateSessionRequest{
			Message:      "message to sign",
			SigningMeans: irmaService.ContractFormat,
		}
		ctx.signerMock.EXPECT().StartSigningSession(gomock.Any()).Return(irmaService.SessionPtr{ID: "abc-sessionid-abc", QrCodeInfo: irma.Qr{URL: qrURL, Type: irma.ActionSigning}}, nil)

		result, err := ctx.contractService.CreateSigningSession(request)

		if !assert.NoError(t, err) {
			return
		}

		irmaResult := result.(irmaService.SessionPtr)

		assert.Equal(t, irmaResult.QrCodeInfo.URL, qrURL, "qrCode should contain the correct URL")
		assert.Equal(t, irmaResult.QrCodeInfo.Type, irma.ActionSigning, "qrCode type should be signing")
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

func TestContract_Configure(t *testing.T) {
	t.Run("ok - config valid", func(t *testing.T) {
		c := service{
			config: Config{
				Mode:                      core.ServerEngineMode,
				PublicURL:                 "url",
				ActingPartyCn:             "url",
				IrmaConfigPath:            "../../../testdata/irma",
				SkipAutoUpdateIrmaSchemas: true,
				ContractValidators:        []string{"irma", "dummy"},
			},
		}

		if assert.NoError(t, c.Configure()) {
			// BUG: nuts-auth#23
			assert.True(t, c.contractValidator.IsInitialized())
		}
	})
}

func TestContract_VerifyVP(t *testing.T) {
	t.Run("ok - valid VP", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		rawVP, err := json.Marshal(struct {
			Type []string
		}{Type: []string{"bar"}})
		if !assert.NoError(t, err) {
			return
		}

		mockVerifier := servicesMock.NewMockContractClient(ctrl)
		mockVerifier.EXPECT().VerifyVP(rawVP).Return(&contract.VerificationResult{State: contract.Valid}, nil)

		validator := service{verifiers: map[string]contract.Verifier{"bar": mockVerifier}}

		validationResult, err := validator.VerifyVP(rawVP)

		if !assert.NoError(t, err) {
			return
		}
		if !assert.NotNil(t, validationResult) {
			return
		}
		assert.Equal(t, contract.Valid, validationResult.State)
	})

	t.Run("nok - unknown VerifiablePresentation", func(t *testing.T) {
		validator := service{}

		rawVP, err := json.Marshal(struct {
			Type []string
		}{Type: []string{"bar"}})
		if !assert.NoError(t, err) {
			return
		}

		validationResult, err := validator.VerifyVP(rawVP)
		if !assert.Error(t, err) {
			return
		}
		if !assert.Nil(t, validationResult) {
			return
		}
		assert.Equal(t, "unknown VerifiablePresentation type: bar", err.Error())
	})

	t.Run("nok - missing custom type", func(t *testing.T) {
		validator := service{}

		rawVP, err := json.Marshal(struct {
			foo string
		}{foo: "bar"})
		if !assert.NoError(t, err) {
			return
		}

		validationResult, err := validator.VerifyVP(rawVP)
		if !assert.Error(t, err) {
			return
		}
		if !assert.Nil(t, validationResult) {
			return
		}
		assert.Equal(t, "unprocessable VerifiablePresentation, exactly 1 custom type is expected", err.Error())
	})

	t.Run("nok - invalid rawVP", func(t *testing.T) {
		validator := service{}
		validationResult, err := validator.VerifyVP([]byte{})
		if !assert.Error(t, err) {
			return
		}
		if !assert.Nil(t, validationResult) {
			return
		}
		assert.Equal(t, "unable to verifyVP: unexpected end of JSON input", err.Error())
	})
}

func TestContract_SigningSessionStatus(t *testing.T) {
	t.Run("ok - valid session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		sessionID := "123"

		mockSigner := contractMock.NewMockSigner(ctrl)
		mockSigner.EXPECT().SigningSessionStatus(sessionID).Return(&contractMock.MockSigningSessionResult{}, nil)

		validator := service{signers: map[string]contract.Signer{"bar": mockSigner}}

		signingSessionResult, err := validator.SigningSessionStatus(sessionID)
		if !assert.NoError(t, err) {
			return
		}
		if !assert.NotNil(t, signingSessionResult) {
			return
		}
	})

	t.Run("nok - session not found", func(t *testing.T) {
		validator := service{}
		sessionID := "123"
		signingSesionResult, err := validator.SigningSessionStatus(sessionID)

		if !assert.Error(t, err) {
			return
		}
		if !assert.Nil(t, signingSesionResult) {
			return
		}
		assert.Equal(t, "session not found", err.Error())
	})
}

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
	cryptoClient := cryptoMock.NewMockClient(ctrl)
	registryClient := registryMock.NewMockRegistryClient(ctrl)
	contractValidatorMock := servicesMock.NewMockContractValidator(ctrl)
	contractSessionHandler := servicesMock.NewMockContractSessionHandler(ctrl)

	signers := map[string]contract.Signer{}
	signerMock := contractMock.NewMockSigner(ctrl)
	signers["irma"] = signerMock

	return &testContext{
		ctrl:                   ctrl,
		cryptoMock:             cryptoClient,
		registryMock:           registryClient,
		contractValidatorMock:  contractValidatorMock,
		contractSessionHandler: contractSessionHandler,
		signerMock:             signerMock,
		contractService: &service{
			config: Config{
				ActingPartyCn: "actingPartyCn",
			},
			contractSessionHandler: contractSessionHandler,
			contractValidator:      contractValidatorMock,
			crypto:                 cryptoClient,
			registry:               registryClient,
			signers:                signers,
		},
	}
}
