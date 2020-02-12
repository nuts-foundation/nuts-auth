package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

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

		tt := time.Now().Truncate(time.Second)

		authMock.EXPECT().CreateContractSession(pkg.CreateSessionRequest{
			Type:      "BehandelaarLogin",
			Version:   "v1",
			Language:  "NL",
			ValidFrom: tt,
			ValidTo:   tt.Add(time.Hour * 13),
		}, gomock.Any()).Return(&pkg.CreateSessionResult{
			QrCodeInfo: irma.Qr{
				URL:  "http://example.com/auth/irmaclient/123",
				Type: irma.Action("signing")},
			SessionID: "abc-sessionid",
		}, nil)

		wrapper := Wrapper{Auth: authMock}
		vf := tt.Format("2006-01-02T15:04:05-07:00")
		vt := tt.Add(time.Hour * 13).Format("2006-01-02T15:04:05-07:00")
		params := ContractSigningRequest{
			Type:      "BehandelaarLogin",
			Language:  "NL",
			Version:   "v1",
			ValidFrom: &vf,
			ValidTo:   &vt,
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
		}).Return(&pkg.ContractValidationResult{
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

type OAuthErrorMatcher struct {
	x AccessTokenRequestFailedResponse
}

func (e OAuthErrorMatcher) Matches(x interface{}) bool {
	if !reflect.TypeOf(x).AssignableTo(reflect.TypeOf(x)) {
		return false
	}

	response := x.(*AccessTokenRequestFailedResponse)
	return e.x.Error == response.Error && *e.x.ErrorDescription == *response.ErrorDescription
}

func (e OAuthErrorMatcher) String() string {
	return fmt.Sprintf("is equal to {%v, %v}", e.x.Error, *e.x.ErrorDescription)
}

func TestWrapper_NutsAuthCreateAccessToken(t *testing.T) {
	type CreateAccessTokenTestContext struct {
		ctrl     *gomock.Controller
		echoMock *mock.MockContext
		authMock *mock2.MockAuthClient
		wrapper  Wrapper
	}

	createContext := func(t *testing.T) *CreateAccessTokenTestContext {
		ctrl := gomock.NewController(t)
		authMock := mock2.NewMockAuthClient(ctrl)
		return &CreateAccessTokenTestContext{
			ctrl:     ctrl,
			echoMock: mock.NewMockContext(ctrl),
			authMock: authMock,
			wrapper:  Wrapper{Auth: authMock},
		}
	}

	bindPostBody := func(ctx *CreateAccessTokenTestContext, body CreateAccessTokenRequest) {
		ctx.echoMock.EXPECT().FormValue("assertion").Return(body.Assertion)
		ctx.echoMock.EXPECT().FormValue("grant_type").Return(body.GrantType)
	}

	expectError := func(ctx *CreateAccessTokenTestContext, err AccessTokenRequestFailedResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusBadRequest, OAuthErrorMatcher{x: err})
	}

	expectStatusOK := func(ctx *CreateAccessTokenTestContext, response AccessTokenResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusOK, gomock.Eq(response))
	}

	t.Run("unknown grant_type", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "unknown type"}
		bindPostBody(ctx, params)

		errorDescription := "grant_type must be: 'urn:ietf:params:oauth:grant-type:jwt-bearer'"
		errorType := "unsupported_grant_type"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: &errorDescription, Error: errorType}
		expectError(ctx, errorResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("invalid assertion", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: "invalid jwt"}
		bindPostBody(ctx, params)

		errorDescription := "Assertion must be a valid encoded jwt"
		errorType := "invalid_grant"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: &errorDescription, Error: errorType}
		expectError(ctx, errorResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	const validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6NDgwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjoxNTc4MTEwNDgxLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.76XtU81IyR3Ak_2fgrYsuLcvxndf0eedT1mFPa-rPXk"

	t.Run("create token returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		errorDescription := "oh boy"
		errorType := "invalid_grant"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: &errorDescription, Error: errorType}
		expectError(ctx, errorResponse)

		ctx.authMock.EXPECT().CreateAccessToken(pkg.CreateAccessTokenRequest{JwtString: validJwt}).Return(nil, fmt.Errorf("oh boy"))
		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("valid request", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		pkgResponse := &pkg.AccessTokenResponse{AccessToken: "foo"}
		ctx.authMock.EXPECT().CreateAccessToken(pkg.CreateAccessTokenRequest{JwtString: validJwt}).Return(pkgResponse, nil)

		apiResponse := AccessTokenResponse{AccessToken: pkgResponse.AccessToken}
		expectStatusOK(ctx, apiResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)

	})

}

func TestWrapper_NutsAuthCreateJwtBearerToken(t *testing.T) {
	type CreateJwtBearerTokenContext struct {
		ctrl     *gomock.Controller
		echoMock *mock.MockContext
		authMock *mock2.MockAuthClient
		wrapper  Wrapper
	}

	createContext := func(t *testing.T) *CreateJwtBearerTokenContext {
		ctrl := gomock.NewController(t)
		authMock := mock2.NewMockAuthClient(ctrl)
		return &CreateJwtBearerTokenContext{
			ctrl:     ctrl,
			echoMock: mock.NewMockContext(ctrl),
			authMock: authMock,
			wrapper:  Wrapper{Auth: authMock},
		}
	}

	bindPostBody := func(ctx *CreateJwtBearerTokenContext, body CreateJwtBearerTokenRequest) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	expectStatusOK := func(ctx *CreateJwtBearerTokenContext, response JwtBearerTokenResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusOK, response)
	}

	t.Run("make request", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		body := CreateJwtBearerTokenRequest{
			Actor:     "urn:oid:2.16.840.1.113883.2.4.6.1:48000000",
			Custodian: "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
			Subject:   "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			Identity:  "irma-token",
		}
		bindPostBody(ctx, body)
		response := JwtBearerTokenResponse{
			BearerToken: "123.456.789",
		}
		ctx.authMock.EXPECT().CreateJwtBearerToken(gomock.Any()).Return(&pkg.JwtBearerAccessTokenResponse{BearerToken: response.BearerToken}, nil)
		expectStatusOK(ctx, response)

		if !assert.Nil(t, ctx.wrapper.CreateJwtBearerToken(ctx.echoMock)) {
			t.FailNow()
		}
	})
}
