package api

import (
	"encoding/json"
	"errors"
	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	mock2 "github.com/nuts-foundation/nuts-auth/mock"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-go/mock"
	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"
	"net/http"
	"testing"
)

func TestWrapper_NutsAuthCreateSession(t *testing.T) {
	t.Run("with valid params", func(t *testing.T) {

		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoMock := mock.NewMockContext(ctrl)
		authMock := mock2.NewMockAuthClient(ctrl)

		authMock.EXPECT().CreateContractSession(pkg.CreateSessionRequest{
			Type:     "BehandelaarLogin",
			Version:  "v1",
			Language: "NL",
		}, gomock.Any()).Return(&pkg.CreateSessionResult{
			QrCodeInfo: irma.Qr{
				URL:  "http://example.com/auth/irmaclient/123",
				Type: irma.Action("signing")},
			SessionId: "abc-sessionid",
		}, nil)

		wrapper := Wrapper{Auth: authMock}
		params := ContractSigningRequest{
			Type:     "BehandelaarLogin",
			Language: "NL",
			Version:  "v1",
		}

		jsonData, _ := json.Marshal(params)

		echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ := json.Unmarshal(jsonData, f)
		})
		echoMock.EXPECT().JSON(http.StatusCreated, CreateSessionResult{
			QrCodeInfo: IrmaQR{U: "http://example.com/auth/irmaclient/123",
				Irmaqr: "signing",
			}, SessionId: "abc-sessionid"})

		err := wrapper.NutsAuthCreateSession(echoMock)

		assert.Nil(t, err)
	})

	t.Run("with invalid params", func(t *testing.T) {
		wrapper := Wrapper{}
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoMock := mock.NewMockContext(ctrl)

		echoMock.EXPECT().Bind(gomock.Any()).Return(errors.New("unable to parse body"))
		err := wrapper.NutsAuthCreateSession(echoMock)
		assert.Error(t, err)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})

	t.Run("with an unknown contract", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoMock := mock.NewMockContext(ctrl)
		authMock := mock2.NewMockAuthClient(ctrl)

		params := ContractSigningRequest{
			Type:     "UnknownContract",
			Language: "NL",
			Version:  "v1",
		}

		authMock.EXPECT().CreateContractSession(pkg.CreateSessionRequest{
			Type:     pkg.ContractType(params.Type),
			Version:  "v1",
			Language: "NL",
		}, gomock.Any()).Return(
			nil, pkg.ErrContractNotFound)

		wrapper := Wrapper{Auth: authMock}

		jsonData, _ := json.Marshal(params)
		echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ := json.Unmarshal(jsonData, f)
		})

		err := wrapper.NutsAuthCreateSession(echoMock)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})
}
