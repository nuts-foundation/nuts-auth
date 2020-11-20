package experimental

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	core "github.com/nuts-foundation/nuts-go-core"
	coreMock "github.com/nuts-foundation/nuts-go-core/mock"
	"github.com/stretchr/testify/assert"

	pkg2 "github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

type TestContext struct {
	ctrl     *gomock.Controller
	echoMock *coreMock.MockContext
	authMock pkg2.AuthClient
	wrapper  Wrapper
}

type mockAuthClient struct {
}

func (m mockAuthClient) OAuthClient() services.OAuthClient {
	panic("implement me")
}

func (m mockAuthClient) ContractClient() services.ContractClient {
	panic("implement me")
}

type mockContractNotary struct {
}

func (m mockContractNotary) DrawUpContract(template contract.Template, orgID core.PartyID) (*contract.Contract, error) {
	return &contract.Contract{
		RawContractText: "drawn up contract text",
		Template:        &template,
		Params:          nil,
	}, nil
}

func (m mockAuthClient) ContractNotary() services.ContractNotary {
	return mockContractNotary{}
}

func createContext(t *testing.T) TestContext {
	t.Helper()
	ctrl := gomock.NewController(t)
	authMock := mockAuthClient{}
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
		defer ctx.ctrl.Finish()

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

func TestWrapper_DrawUpContract(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body DrawUpContractRequest) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	t.Run("it can draw up a standard contract", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := DrawUpContractRequest{
			Language:    ContractLanguage("EN"),
			Type:        ContractType("PractitionerLogin"),
			Version:     ContractVersion("v3"),
			LegalEntity: LegalEntity("urn:oid:1.2.3.4:foo"),
		}
		bindPostBody(&ctx, params)

		expectedResponse := ContractResponse{
			Language: ContractLanguage("EN"),
			Message:  "drawn up contract text",
			Type:     ContractType("PractitionerLogin"),
			Version:  ContractVersion("v3"),
		}
		ctx.echoMock.EXPECT().JSON(http.StatusOK, expectedResponse)
		err := ctx.wrapper.DrawUpContract(ctx.echoMock)
		assert.NoError(t, err)

	})
}
