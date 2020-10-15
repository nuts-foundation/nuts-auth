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

package pkg

import (
	"errors"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	"github.com/nuts-foundation/nuts-crypto/test/mock"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"
)

func TestAuth_CreateContractSession(t *testing.T) {
	RegisterTestDependencies(t)
	t.Run("Create a new session", func(t *testing.T) {
		sut := Contract{
			ContractSessionHandler: MockContractSessionHandler{},
			ContractTemplates:      contract.StandardContractTemplates,
			Config:                 AuthConfig{ActingPartyCn: "0001"},
		}
		request := services.CreateSessionRequest{
			Type:        contract.Type("BehandelaarLogin"),
			Language:    contract.Language("NL"),
			LegalEntity: "vendorName",
		}
		result, err := sut.CreateContractSession(request)

		if !assert.NoError(t, err) {
			return
		}

		assert.Equal(t, result.QrCodeInfo.URL, qrURL, "qrCode should contain the correct URL")
		assert.Equal(t, result.QrCodeInfo.Type, irma.ActionSigning, "qrCode type should be signing")
	})

	t.Run("Unknown contract returns an error", func(t *testing.T) {
		sut := Contract{
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
	RegisterTestDependencies(t)
	sut := Contract{ContractTemplates: contract.StandardContractTemplates}
	t.Run("get contract by type", func(t *testing.T) {
		result, err := sut.ContractByType(contract.Type("BehandelaarLogin"), contract.Language("NL"), contract.Version("v1"))

		if !assert.Nil(t, err) || !assert.NotNil(t, result) {
			return
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

func TestAuth_ContractSessionStatus(t *testing.T) {
	RegisterTestDependencies(t)
	t.Run("returns err if session is not found", func(t *testing.T) {
		i := &Contract{
			ContractSessionHandler: MockContractSessionHandler{},
		}

		_, err := i.ContractSessionStatus("ID")

		assert.True(t, errors.Is(err, services.ErrSessionNotFound))
	})

	t.Run("returns session status when found", func(t *testing.T) {
		i := &Contract{
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
	RegisterTestDependencies(t)
	t.Run("Returns error on unknown constract type", func(t *testing.T) {
		i := &Contract{
			ContractValidator: MockContractValidator{},
		}

		_, err := i.ValidateContract(services.ValidationRequest{ContractFormat: "Unknown"})

		assert.True(t, errors.Is(err, contract.ErrUnknownContractFormat))
	})

	t.Run("Returns validation result for JWT", func(t *testing.T) {
		i := &Contract{
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
		i := &Contract{
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

func TestAuth_KeyExistsFor(t *testing.T) {
	RegisterTestDependencies(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	cryptoMock := mock.NewMockClient(ctrl)
	auth := &Contract{
		Crypto: cryptoMock,
	}

	t.Run("false when nutsCrypto returns false", func(t *testing.T) {
		cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(false)

		orgID := auth.KeyExistsFor(OrganizationID)
		assert.False(t, orgID)
	})

	t.Run("true when nutsCrypto returns false", func(t *testing.T) {
		cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(true)

		assert.True(t, auth.KeyExistsFor(OrganizationID))
	})
}

func TestAuth_OrganizationNameById(t *testing.T) {
	RegisterTestDependencies(t)
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	registry := registryMock.NewMockRegistryClient(ctrl)
	auth := &Contract{
		Registry: registry,
	}

	t.Run("returns name", func(t *testing.T) {
		registry.EXPECT().OrganizationById(OrganizationID).Return(&db.Organization{Name: "name"}, nil)

		name, err := auth.OrganizationNameByID(OrganizationID)
		if assert.NoError(t, err) {
			assert.Equal(t, "name", name)
		}
	})

	t.Run("returns error", func(t *testing.T) {
		registry.EXPECT().OrganizationById(gomock.Any()).Return(nil, errors.New("error"))

		_, err := auth.OrganizationNameByID(OrganizationID)
		assert.Error(t, err)
	})
}
