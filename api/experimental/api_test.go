package experimental

import (
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	coreMock "github.com/nuts-foundation/nuts-go-core/mock"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-auth/mock"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

type TestContext struct {
	ctrl     *gomock.Controller
	echoMock *coreMock.MockContext
	authMock *mock.MockAuthClient
	wrapper  Wrapper
}

func createContext(t *testing.T) TestContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	authMock := mock.NewMockAuthClient(ctrl)
	return TestContext{
		ctrl:     ctrl,
		echoMock: coreMock.NewMockContext(ctrl),
		authMock: authMock,
		wrapper:  Wrapper{Auth: authMock},
	}
}

func TestWrapper_GetContractTemplate(t *testing.T) {
	t.Run("it can retrieve a ContractTemplate", func(t *testing.T) {
		ctx := createContext(t)
		expectedContract := contract.StandardContractTemplates["EN"]["PractitionerLogin"]["v1"]
		response := ContractTemplateResponse{
			Language: ContractLanguage(expectedContract.Language),
			Template: expectedContract.Template,
			Type:     ContractType(expectedContract.Type),
			Version:  ContractVersion(expectedContract.Version),
		}
		ctx.echoMock.EXPECT().JSON(http.StatusOK, response)
		err := ctx.wrapper.GetContractTemplate(ctx.echoMock, "EN", "PractitionerLogin", GetContractTemplateParams{Version: nil})
		if !assert.NoError(t, err) {
			return
		}
	})

}
