package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	mock2 "github.com/nuts-foundation/nuts-auth/mock"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-go-core/mock"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"
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
			// FIXME: use actual actingPartyCN here
		}, gomock.Any()).Return(&pkg.CreateSessionResult{
			QrCodeInfo: irma.Qr{
				URL:  "http://example.com/auth/irmaclient/123",
				Type: irma.Action("signing")},
			SessionID: "abc-sessionid",
		}, nil)

		wrapper := Wrapper{Auth: authMock}
		params := ContractSigningRequest{
			Type:     "BehandelaarLogin",
			Language: "NL",
			Version:  "v1",
		}

		jsonData, _ := json.Marshal(params)

		echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
		echoMock.EXPECT().JSON(http.StatusCreated, CreateSessionResult{
			QrCodeInfo: IrmaQR{U: "http://example.com/auth/irmaclient/123",
				Irmaqr: "signing",
			}, SessionId: "abc-sessionid"})

		err := wrapper.CreateSession(echoMock)

		assert.Nil(t, err)
	})

	t.Run("with invalid params", func(t *testing.T) {
		wrapper := Wrapper{}
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoMock := mock.NewMockContext(ctrl)

		echoMock.EXPECT().Bind(gomock.Any()).Return(errors.New("unable to parse body"))
		err := wrapper.CreateSession(echoMock)
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
			_ = json.Unmarshal(jsonData, f)
		})

		err := wrapper.CreateSession(echoMock)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})
}

func TestWrapper_NutsAuthSessionRequestStatus(t *testing.T) {
	t.Run("get status of a known session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoMock := mock.NewMockContext(ctrl)
		authMock := mock2.NewMockAuthClient(ctrl)

		sessionID := "123"
		nutsAuthToken := "123.456.123"
		proofStatus := "VALID"

		authMock.EXPECT().ContractSessionStatus(sessionID).Return(&pkg.SessionStatusResult{
			SessionResult: server.SessionResult{
				Status: "INITIALIZED",
				Token:  "YRnWbPJ7ffKCnf9cP51e",
				Type:   "signing",
				Disclosed: [][]*irma.DisclosedAttribute{
					{{Value: irma.TranslatedString(map[string]string{"nl": "00000001"})}},
				},
				ProofStatus: irma.ProofStatusValid,
			},
			NutsAuthToken: nutsAuthToken,
		}, nil)

		a := []DisclosedAttribute{
			{
				Value: DisclosedAttribute_Value{
					AdditionalProperties: map[string]string{"nl": "00000001"},
				},
			},
		}
		echoMock.EXPECT().JSON(http.StatusOK, SessionResult{
			Status:        "INITIALIZED",
			Token:         "YRnWbPJ7ffKCnf9cP51e",
			Type:          "signing",
			Disclosed:     &a,
			NutsAuthToken: &nutsAuthToken,
			ProofStatus:   &proofStatus,
		})
		wrapper := Wrapper{Auth: authMock}
		err := wrapper.SessionRequestStatus(echoMock, sessionID)
		assert.Nil(t, err)
	})

	t.Run("try to get a status of an unknown session", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoMock := mock.NewMockContext(ctrl)
		authMock := mock2.NewMockAuthClient(ctrl)

		sessionID := "123"

		authMock.EXPECT().ContractSessionStatus(sessionID).Return(nil, pkg.ErrSessionNotFound)
		wrapper := Wrapper{Auth: authMock}

		err := wrapper.SessionRequestStatus(echoMock, sessionID)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusNotFound, httpError.Code)
	})
}

func TestWrapper_NutsAuthValidateContract(t *testing.T) {
	t.Run("ValidateContract", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoMock := mock.NewMockContext(ctrl)
		authMock := mock2.NewMockAuthClient(ctrl)

		params := ValidationRequest{
			ActingPartyCn:  "DemoEHR",
			ContractFormat: "JWT",
			ContractString: "base64encodedContractString",
		}

		jsonData, _ := json.Marshal(params)
		echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		sa := ValidationResult_SignerAttributes{AdditionalProperties: map[string]string{"nl": "00000007"}}
		echoMock.EXPECT().JSON(http.StatusOK, ValidationResult{
			ContractFormat:   string(pkg.JwtFormat),
			ValidationResult: "VALID",
			SignerAttributes: sa,
		})

		authMock.EXPECT().ValidateContract(pkg.ValidationRequest{
			ActingPartyCN:  "DemoEHR",
			ContractFormat: pkg.JwtFormat,
			ContractString: "base64encodedContractString",
		}).Return(&pkg.ValidationResult{
			ValidationResult:    "VALID",
			ContractFormat:      pkg.JwtFormat,
			DisclosedAttributes: map[string]string{"nl": "00000007"},
		}, nil)

		wrapper := Wrapper{Auth: authMock}
		err := wrapper.ValidateContract(echoMock)

		assert.Nil(t, err)
	})

}

func TestWrapper_NutsAuthGetContractByType(t *testing.T) {
	t.Run("get known contact", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoMock := mock.NewMockContext(ctrl)
		authMock := mock2.NewMockAuthClient(ctrl)

		cType := "KnownContract"
		cVersion := "v1"
		cLanguage := "NL"
		params := GetContractByTypeParams{
			Version:  &cVersion,
			Language: &cLanguage,
		}

		contract := pkg.Contract{
			Type:               pkg.ContractType(cType),
			Version:            pkg.Version(cVersion),
			Language:           pkg.Language(cLanguage),
			TemplateAttributes: []string{"party"},
			Template:           "ik geen toestemming aan {{party}}",
		}

		ta := []string{"party"}
		answer := Contract{
			Type:               Type(cType),
			Template:           &contract.Template,
			Version:            Version(cVersion),
			TemplateAttributes: &ta,
			Language:           Language(cLanguage),
		}

		authMock.EXPECT().ContractByType(pkg.ContractType(cType), pkg.Language(cLanguage), pkg.Version(cVersion)).Return(&contract, nil)
		echoMock.EXPECT().JSON(http.StatusOK, answer)

		wrapper := Wrapper{Auth: authMock}
		err := wrapper.GetContractByType(echoMock, cType, params)

		assert.Nil(t, err)
	})

	t.Run("get an unknown contract", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()
		echoMock := mock.NewMockContext(ctrl)
		authMock := mock2.NewMockAuthClient(ctrl)

		cType := "UnknownContract"
		params := GetContractByTypeParams{}

		authMock.EXPECT().ContractByType(pkg.ContractType(cType), pkg.Language(""), pkg.Version("")).Return(nil, pkg.ErrContractNotFound)

		wrapper := Wrapper{Auth: authMock}
		err := wrapper.GetContractByType(echoMock, cType, params)

		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusNotFound, httpError.Code)

	})
}
