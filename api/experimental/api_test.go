package experimental

import (
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	core "github.com/nuts-foundation/nuts-go-core"
	coreMock "github.com/nuts-foundation/nuts-go-core/mock"
	"github.com/stretchr/testify/assert"

	services2 "github.com/nuts-foundation/nuts-auth/mock/services"
	pkg2 "github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	"github.com/nuts-foundation/nuts-auth/pkg/services/dummy"
)

type TestContext struct {
	ctrl     *gomock.Controller
	echoMock *coreMock.MockContext
	authMock pkg2.AuthClient
	wrapper  Wrapper
}

type mockAuthClient struct {
	ctrl gomock.Controller
}

func (m mockAuthClient) OAuthClient() services.OAuthClient {
	panic("implement me")
}

func (m mockAuthClient) ContractClient() services.ContractClient {
	dummyMeans := dummy.Dummy{
		InStrictMode: false,
		Sessions:     map[string]string{},
		Status:       map[string]string{},
	}

	contractClient := services2.NewMockContractClient(&m.ctrl)
	contractClient.EXPECT().CreateSigningSession(gomock.Any()).DoAndReturn(
		func(sessionRequest services.CreateSessionRequest) (contract.SessionPointer, error) {
			return dummyMeans.StartSigningSession(sessionRequest.Message)
		})
	return contractClient
}

type mockContractNotary struct {
}

func (m mockContractNotary) ValidateContract(contractToValidate contract.Contract, orgID core.PartyID, checkTime time.Time) (bool, error) {
	panic("implement me")
}

func (m mockContractNotary) DrawUpContract(template contract.Template, orgID core.PartyID, validFrom time.Time, validDuration time.Duration) (*contract.Contract, error) {
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
	authMock := mockAuthClient{ctrl: *ctrl}
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

type signSessionResponseMatcher struct {
	means string
}

func (s signSessionResponseMatcher) Matches(x interface{}) bool {
	if !reflect.TypeOf(x).AssignableTo(reflect.TypeOf(x)) {
		return false
	}

	return x.(CreateSignSessionResult).Means == s.means && x.(CreateSignSessionResult).SessionPtr["sessionID"] != ""
}

func (s signSessionResponseMatcher) String() string {
	return fmt.Sprintf("{%v somePtr}", s.means)
}

func TestWrapper_CreateSignSession(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body CreateSignSessionRequest) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	t.Run("create a dummy signing session", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		postParams := CreateSignSessionRequest{
			Means:   "dummy",
			Payload: "this is the contract message to agree to",
		}
		bindPostBody(&ctx, postParams)

		ctx.echoMock.EXPECT().JSON(http.StatusCreated, signSessionResponseMatcher{means: "dummy"})
		err := ctx.wrapper.CreateSignSession(ctx.echoMock)
		assert.NoError(t, err)
	})
}
