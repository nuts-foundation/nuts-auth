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
