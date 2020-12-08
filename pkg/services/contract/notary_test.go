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
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	cryptoMock "github.com/nuts-foundation/nuts-crypto/test/mock"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"github.com/nuts-foundation/nuts-registry/test"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

func Test_contractNotaryService_ValidateContract(t *testing.T) {
	t.Run("it could validate a valid contract", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		registryMock := mock.NewMockRegistryClient(ctrl)
		cns := contractNotaryService{Registry: registryMock}

		contractTemplate, err := contract.StandardContractTemplates.FindFromRawContractText("EN:PractitionerLogin:v3")
		if !assert.NoError(t, err) {
			return
		}

		orgID, err := core.ParsePartyID("urn:oid:1.2.3.4:556611")
		if !assert.NoError(t, err) {
			return
		}
		orgName := "zorginstelling het hoekje"
		registryMock.EXPECT().ReverseLookup(orgName).Return(&db.Organization{Identifier: orgID}, nil)

		contractToCheck, err := contractTemplate.Render(map[string]string{
			contract.LegalEntityAttr: orgName,
		}, time.Now().Add(-10*time.Minute), 20*time.Minute)
		if !assert.NoError(t, err) {
			return
		}

		ok, err := cns.ValidateContract(*contractToCheck, orgID, time.Now())
		assert.True(t, ok)
		assert.NoError(t, err)
	})
}
func Test_contractNotaryService_KeyExistsFor(t *testing.T) {

	var organizationID = test.OrganizationID("00000001")

	t.Run("false when nutsCrypto returns false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cryptoMock := cryptoMock.NewMockClient(ctrl)
		notary := contractNotaryService{Crypto: cryptoMock}
		cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(false)

		orgID := notary.KeyExistsFor(organizationID)
		assert.False(t, orgID)
	})

	t.Run("true when nutsCrypto returns false", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		cryptoMock := cryptoMock.NewMockClient(ctrl)
		notary := contractNotaryService{Crypto: cryptoMock}
		cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(true)

		assert.True(t, notary.KeyExistsFor(organizationID))
	})
}

func Test_contractNotaryService_DrawUpContract(t *testing.T) {
	type testContext struct {
		ctrl         *gomock.Controller
		cryptoMock   *cryptoMock.MockClient
		registryMock *mock.MockRegistryClient
		notary       contractNotaryService
	}
	buildContext := func(t *testing.T) *testContext {
		ctrl := gomock.NewController(t)
		ctx := &testContext{
			ctrl:         ctrl,
			cryptoMock:   cryptoMock.NewMockClient(ctrl),
			registryMock: mock.NewMockRegistryClient(ctrl),
		}
		notary := contractNotaryService{
			Registry:         ctx.registryMock,
			Crypto:           ctx.cryptoMock,
			ContractValidity: 15 * time.Minute,
		}
		ctx.notary = notary
		return ctx
	}

	template := contract.Template{
		Template: "Organisation Name: {{legal_entity}}, valid from {{valid_from}} to {{valid_to}}",
	}
	orgID := core.PartyID{}
	// Add 1 second so !time.Zero()
	validFrom := time.Time{}.Add(time.Second)
	duration := 10 * time.Minute

	t.Run("draw up valid contract", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).AnyTimes().Return(true)
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).AnyTimes().Return(&db.Organization{Name: "CareBears"}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears, valid from maandag, 1 januari 0001 00:19:33 to maandag, 1 januari 0001 00:29:33", drawnUpContract.RawContractText)
	})

	t.Run("no given duration uses default", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).AnyTimes().Return(true)
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).AnyTimes().Return(&db.Organization{Name: "CareBears"}, nil)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, 0)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears, valid from maandag, 1 januari 0001 00:19:33 to maandag, 1 januari 0001 00:34:33", drawnUpContract.RawContractText)
	})

	t.Run("no given time uses time.Now()", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).AnyTimes().Return(true)
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).AnyTimes().Return(&db.Organization{Name: "CareBears"}, nil)

		timeNow = func() time.Time {
			return time.Time{}.Add(10 * time.Second)
		}
		defer func() { timeNow = time.Now }()
		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, time.Time{}, 0)
		if !assert.NoError(t, err) {
			return
		}

		assert.NotNil(t, drawnUpContract)
		assert.Equal(t, "Organisation Name: CareBears, valid from maandag, 1 januari 0001 00:19:42 to maandag, 1 januari 0001 00:34:42", drawnUpContract.RawContractText)
	})

	t.Run("nok - unknown private key", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(false)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: organization is not managed by this node: missing organization private key", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - unknown organization", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(true)
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(nil, db.ErrOrganizationNotFound)

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: organization not found", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})

	t.Run("nok - render error", func(t *testing.T) {
		ctx := buildContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(gomock.Any()).Return(true)
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(&db.Organization{Name: "CareBears"}, nil)

		template := contract.Template{
			Template: "Organisation Name: {{{legal_entity}}, valid from {{valid_from}} to {{valid_to}}",
		}

		drawnUpContract, err := ctx.notary.DrawUpContract(template, orgID, validFrom, duration)
		if assert.Error(t, err) {
			assert.Equal(t, "could not draw up contract: could not render contract template: line 1: unmatched open tag", err.Error())
		}
		assert.Nil(t, drawnUpContract)
	})
}
