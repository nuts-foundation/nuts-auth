package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"
	"time"

	servicesMock "github.com/nuts-foundation/nuts-auth/mock/services"
	"github.com/nuts-foundation/nuts-auth/pkg/services"

	irmaService "github.com/nuts-foundation/nuts-auth/pkg/services/irma"

	contract2 "github.com/nuts-foundation/nuts-auth/pkg/contract"

	"github.com/nuts-foundation/nuts-registry/test"

	"github.com/dgrijalva/jwt-go"

	"github.com/golang/mock/gomock"
	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-auth/mock"
	coreMock "github.com/nuts-foundation/nuts-go-core/mock"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/stretchr/testify/assert"
)

var careOrgID = test.OrganizationID("987")
var careOrgName = "care organization"

func TestWrapper_NutsAuthCreateSession(t *testing.T) {
	t.Run("with valid params", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tt := time.Now().Truncate(time.Second)

		ctx.contractMock.EXPECT().KeyExistsFor(gomock.Any()).Return(true)
		ctx.contractMock.EXPECT().OrganizationNameByID(careOrgID).Return(careOrgName, nil)

		ctx.contractMock.EXPECT().CreateContractSession(services.CreateSessionRequest{
			Type:        "BehandelaarLogin",
			Version:     "v1",
			Language:    "NL",
			ValidFrom:   tt,
			ValidTo:     tt.Add(time.Hour * 13),
			LegalEntity: careOrgName,
		}).Return(&services.CreateSessionResult{
			QrCodeInfo: irma.Qr{
				URL:  "http://example.com" + irmaService.IrmaMountPath + "/123",
				Type: "signing"},
			SessionID: "abc-sessionid",
		}, nil)

		wrapper := Wrapper{Auth: ctx.authMock}
		vf := tt.Format("2006-01-02T15:04:05-07:00")
		vt := tt.Add(time.Hour * 13).Format("2006-01-02T15:04:05-07:00")
		params := ContractSigningRequest{
			Type:        "BehandelaarLogin",
			Language:    "NL",
			Version:     "v1",
			ValidFrom:   &vf,
			ValidTo:     &vt,
			LegalEntity: LegalEntity(careOrgID.String()),
		}

		jsonData, _ := json.Marshal(params)

		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
		ctx.echoMock.EXPECT().JSON(http.StatusCreated, CreateSessionResult{
			QrCodeInfo: IrmaQR{U: "http://example.com" + irmaService.IrmaMountPath + "/123",
				Irmaqr: "signing",
			}, SessionId: "abc-sessionid"})

		err := wrapper.CreateSession(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("with malformed time period", func(t *testing.T) {
		wrapper := Wrapper{}
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		jsonData := `{"language":"NL","legalEntity":"legalEntity","type":"BehandelaarLogin","valid_from":"invalid time in valid_from","valid_to":"2020-03-26T00:16:57+01:00","version":"v1"}`

		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(jsonData), f)
		})

		err := wrapper.CreateSession(ctx.echoMock)
		assert.Error(t, err)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Contains(t, httpError.Message, "Could not parse validFrom")
		assert.Equal(t, http.StatusBadRequest, httpError.Code)

		jsonData = `{"language":"NL","legalEntity":"legalEntity","type":"BehandelaarLogin","valid_from":"2020-03-26T00:16:57+01:00","valid_to":"invalid time in validTo","version":"v1"}`

		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal([]byte(jsonData), f)
		})

		err = wrapper.CreateSession(ctx.echoMock)
		assert.Error(t, err)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError = err.(*echo.HTTPError)
		assert.Contains(t, httpError.Message, "Could not parse validTo")
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})

	t.Run("with invalid params", func(t *testing.T) {
		wrapper := Wrapper{}
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.echoMock.EXPECT().Bind(gomock.Any()).Return(errors.New("unable to parse body"))
		err := wrapper.CreateSession(ctx.echoMock)
		assert.Error(t, err)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})

	t.Run("with an unknown contract", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := ContractSigningRequest{
			Type:        "UnknownContract",
			Language:    "NL",
			Version:     "v1",
			LegalEntity: LegalEntity(careOrgID.String()),
		}

		ctx.contractMock.EXPECT().KeyExistsFor(gomock.Any()).Return(true)
		ctx.contractMock.EXPECT().OrganizationNameByID(careOrgID).Return(careOrgName, nil)

		ctx.contractMock.EXPECT().CreateContractSession(services.CreateSessionRequest{
			Type:        contract2.Type(params.Type),
			Version:     "v1",
			Language:    "NL",
			LegalEntity: careOrgName,
		}).Return(
			nil, contract2.ErrContractNotFound)

		wrapper := Wrapper{Auth: ctx.authMock}

		jsonData, _ := json.Marshal(params)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := wrapper.CreateSession(ctx.echoMock)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})

	t.Run("for an unknown legalEntity", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := ContractSigningRequest{
			Type:        "UnknownContract",
			Language:    "NL",
			Version:     "v1",
			LegalEntity: LegalEntity(careOrgID.String()),
		}

		ctx.contractMock.EXPECT().KeyExistsFor(gomock.Any()).Return(false)

		wrapper := Wrapper{Auth: ctx.authMock}

		jsonData, _ := json.Marshal(params)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := wrapper.CreateSession(ctx.echoMock)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})

	t.Run("for an unregistered legal entity", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := ContractSigningRequest{
			Type:        "UnknownContract",
			Language:    "NL",
			Version:     "v1",
			LegalEntity: LegalEntity(careOrgID.String()),
		}

		ctx.contractMock.EXPECT().KeyExistsFor(gomock.Any()).Return(true)
		ctx.contractMock.EXPECT().OrganizationNameByID(careOrgID).Return("", errors.New("error"))

		wrapper := Wrapper{Auth: ctx.authMock}

		jsonData, _ := json.Marshal(params)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		err := wrapper.CreateSession(ctx.echoMock)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusBadRequest, httpError.Code)
	})
}

func TestWrapper_NutsAuthSessionRequestStatus(t *testing.T) {
	t.Run("get status of a known session", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		sessionID := "123"
		nutsAuthToken := "123.456.123"
		proofStatus := "VALID"

		ctx.contractMock.EXPECT().ContractSessionStatus(sessionID).Return(&services.SessionStatusResult{
			SessionResult: server.SessionResult{
				Status: "INITIALIZED",
				Token:  "YRnWbPJ7ffKCnf9cP51e",
				Type:   "signing",
				Disclosed: [][]*irma.DisclosedAttribute{
					{{Value: map[string]string{"nl": "00000001"}}},
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
		ctx.echoMock.EXPECT().JSON(http.StatusOK, SessionResult{
			Status:        "INITIALIZED",
			Token:         "YRnWbPJ7ffKCnf9cP51e",
			Type:          "signing",
			Disclosed:     &a,
			NutsAuthToken: &nutsAuthToken,
			ProofStatus:   &proofStatus,
		})
		wrapper := Wrapper{Auth: ctx.authMock}
		err := wrapper.SessionRequestStatus(ctx.echoMock, sessionID)
		assert.Nil(t, err)
	})

	t.Run("try to get a status of an unknown session", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		sessionID := "123"

		ctx.contractMock.EXPECT().ContractSessionStatus(sessionID).Return(nil, services.ErrSessionNotFound)
		wrapper := Wrapper{Auth: ctx.authMock}

		err := wrapper.SessionRequestStatus(ctx.echoMock, sessionID)
		assert.IsType(t, &echo.HTTPError{}, err)
		httpError := err.(*echo.HTTPError)
		assert.Equal(t, http.StatusNotFound, httpError.Code)
	})
}

func TestWrapper_NutsAuthValidateContract(t *testing.T) {
	t.Run("ValidateContract", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := ValidationRequest{
			ActingPartyCn:  "DemoEHR",
			ContractFormat: "JWT",
			ContractString: "base64encodedContractString",
		}

		jsonData, _ := json.Marshal(params)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})

		sa := ValidationResult_SignerAttributes{AdditionalProperties: map[string]string{"nl": "00000007"}}
		ctx.echoMock.EXPECT().JSON(http.StatusOK, ValidationResult{
			ContractFormat:   string(services.JwtFormat),
			ValidationResult: "VALID",
			SignerAttributes: sa,
		})

		ctx.contractMock.EXPECT().ValidateContract(services.ValidationRequest{
			ActingPartyCN:  "DemoEHR",
			ContractFormat: services.JwtFormat,
			ContractString: "base64encodedContractString",
		}).Return(&services.ContractValidationResult{
			ValidationResult:    "VALID",
			ContractFormat:      services.JwtFormat,
			DisclosedAttributes: map[string]string{"nl": "00000007"},
		}, nil)

		wrapper := Wrapper{Auth: ctx.authMock}
		err := wrapper.ValidateContract(ctx.echoMock)

		assert.Nil(t, err)
	})

}

func TestWrapper_NutsAuthGetContractByType(t *testing.T) {
	t.Run("get known contact", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		cType := "KnownContract"
		cVersion := "v1"
		cLanguage := "NL"
		params := GetContractByTypeParams{
			Version:  &cVersion,
			Language: &cLanguage,
		}

		contract := contract2.Template{
			Type:               contract2.Type(cType),
			Version:            contract2.Version(cVersion),
			Language:           contract2.Language(cLanguage),
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

		ctx.contractMock.EXPECT().ContractByType(contract2.Type(cType), contract2.Language(cLanguage), contract2.Version(cVersion)).Return(&contract, nil)
		ctx.echoMock.EXPECT().JSON(http.StatusOK, answer)

		wrapper := Wrapper{Auth: ctx.authMock}
		err := wrapper.GetContractByType(ctx.echoMock, cType, params)

		assert.Nil(t, err)
	})

	t.Run("get an unknown contract", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		cType := "UnknownContract"
		params := GetContractByTypeParams{}

		ctx.contractMock.EXPECT().ContractByType(contract2.Type(cType), contract2.Language(""), contract2.Version("")).Return(nil, contract2.ErrContractNotFound)

		wrapper := Wrapper{Auth: ctx.authMock}
		err := wrapper.GetContractByType(ctx.echoMock, cType, params)

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

	response := x.(AccessTokenRequestFailedResponse)
	return e.x.Error == response.Error && e.x.ErrorDescription == response.ErrorDescription
}

func (e OAuthErrorMatcher) String() string {
	return fmt.Sprintf("is equal to {%v, %v}", e.x.Error, e.x.ErrorDescription)
}

type TestContext struct {
	ctrl         *gomock.Controller
	echoMock     *coreMock.MockContext
	authMock     *mock.MockAuthClient
	oauthMock    *servicesMock.MockOAuthClient
	contractMock *servicesMock.MockContractClient
	wrapper      Wrapper
}

var createContext = func(t *testing.T) *TestContext {
	ctrl := gomock.NewController(t)
	authMock := mock.NewMockAuthClient(ctrl)
	oauthMock := servicesMock.NewMockOAuthClient(ctrl)
	authMock.EXPECT().OAuthClient().AnyTimes().Return(oauthMock)
	contractMock := servicesMock.NewMockContractClient(ctrl)
	authMock.EXPECT().ContractClient().AnyTimes().Return(contractMock)
	return &TestContext{
		ctrl:         ctrl,
		echoMock:     coreMock.NewMockContext(ctrl),
		authMock:     authMock,
		oauthMock:    oauthMock,
		contractMock: contractMock,
		wrapper:      Wrapper{Auth: authMock},
	}
}

func TestWrapper_NutsAuthCreateAccessToken(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body CreateAccessTokenRequest) {
		ctx.echoMock.EXPECT().FormValue("assertion").Return(body.Assertion)
		ctx.echoMock.EXPECT().FormValue("grant_type").Return(body.GrantType)
	}

	expectError := func(ctx *TestContext, err AccessTokenRequestFailedResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusBadRequest, OAuthErrorMatcher{x: err})
	}

	expectStatusOK := func(ctx *TestContext, response AccessTokenResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusOK, gomock.Eq(response))
	}

	t.Run("unknown grant_type", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "unknown type"}
		bindPostBody(ctx, params)

		errorDescription := "grant_type must be: 'urn:ietf:params:oauth:grant-type:jwt-bearer'"
		errorType := "unsupported_grant_type"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: errorDescription, Error: errorType}
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
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: errorDescription, Error: errorType}
		expectError(ctx, errorResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	const validJwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6NDgwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjoxNTc4MTEwNDgxLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.76XtU81IyR3Ak_2fgrYsuLcvxndf0eedT1mFPa-rPXk"

	vendorIdentifierFromHeader = func(ctx echo.Context) string {
		return "Demo EHR"
	}

	t.Run("auth.CreateAccessToken returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		errorDescription := "oh boy"
		errorType := "invalid_grant"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: errorDescription, Error: errorType}
		expectError(ctx, errorResponse)

		ctx.oauthMock.EXPECT().CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt, VendorIdentifier: "Demo EHR"}).Return(nil, fmt.Errorf("oh boy"))
		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("request without vendor information returns an error", func(t *testing.T) {
		// Overwrite the vendorIdentifierFromHeader function to return an empty string
		vendorIdentifierFromHeader = func(ctx echo.Context) string {
			return ""
		}
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		// Set the vendorIdentifierFromHeader back to working value so other test still work
		defer func() {
			vendorIdentifierFromHeader = func(ctx echo.Context) string {
				return "Demo EHR"
			}
		}()

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		errorDescription := "Vendor identifier missing in header"
		errorType := "invalid_grant"
		errorResponse := AccessTokenRequestFailedResponse{ErrorDescription: errorDescription, Error: errorType}
		expectError(ctx, errorResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)
	})

	t.Run("valid request", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		params := CreateAccessTokenRequest{GrantType: "urn:ietf:params:oauth:grant-type:jwt-bearer", Assertion: validJwt}
		bindPostBody(ctx, params)

		pkgResponse := &services.AccessTokenResult{AccessToken: "foo"}
		ctx.oauthMock.EXPECT().CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: validJwt, VendorIdentifier: "Demo EHR"}).Return(pkgResponse, nil)

		apiResponse := AccessTokenResponse{AccessToken: pkgResponse.AccessToken}
		expectStatusOK(ctx, apiResponse)

		err := ctx.wrapper.CreateAccessToken(ctx.echoMock)

		assert.Nil(t, err)

	})

}

func TestWrapper_NutsAuthCreateJwtBearerToken(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body CreateJwtBearerTokenRequest) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	expectStatusOK := func(ctx *TestContext, response JwtBearerTokenResponse) {
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
			Scope:     "nuts-sso",
		}
		bindPostBody(ctx, body)
		response := JwtBearerTokenResponse{
			BearerToken: "123.456.789",
		}

		expectedRequest := services.CreateJwtBearerTokenRequest{
			Actor:         body.Actor,
			Custodian:     body.Custodian,
			IdentityToken: body.Identity,
			Subject:       body.Subject,
		}

		ctx.oauthMock.EXPECT().CreateJwtBearerToken(expectedRequest).Return(&services.JwtBearerTokenResult{BearerToken: response.BearerToken}, nil)
		expectStatusOK(ctx, response)

		if !assert.Nil(t, ctx.wrapper.CreateJwtBearerToken(ctx.echoMock)) {
			t.FailNow()
		}
	})
}

func TestWrapper_NutsAuthIntrospectAccessToken(t *testing.T) {
	bindPostBody := func(ctx *TestContext, body TokenIntrospectionRequest) {
		ctx.echoMock.EXPECT().FormValue("token").Return(body.Token)
	}

	expectStatusOK := func(ctx *TestContext, response TokenIntrospectionResponse) {
		ctx.echoMock.EXPECT().JSON(http.StatusOK, gomock.Eq(response))
	}

	t.Run("empty token returns active false", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := TokenIntrospectionRequest{Token: ""}
		bindPostBody(ctx, request)

		response := TokenIntrospectionResponse{Active: false}
		expectStatusOK(ctx, response)

		_ = ctx.wrapper.IntrospectAccessToken(ctx.echoMock)
	})

	t.Run("introspect a token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := TokenIntrospectionRequest{Token: "123"}
		bindPostBody(ctx, request)

		aud := "123"
		aid := "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"
		exp := 1581412667
		iat := 1581411767
		iss := "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"
		sid := "urn:oid:2.16.840.1.113883.2.4.6.3:999999990"
		scope := "nuts-sso"

		ctx.oauthMock.EXPECT().IntrospectAccessToken(request.Token).Return(
			&services.NutsAccessToken{
				StandardClaims: jwt.StandardClaims{
					Audience:  aud,
					ExpiresAt: int64(exp),
					IssuedAt:  int64(iat),
					Issuer:    iss,
					Subject:   aid,
				},
				SubjectID: sid,
				Scope:     scope,
			}, nil)

		emptyStr := ""
		response := TokenIntrospectionResponse{
			Active: true,
			Aud:    &aud,
			Exp:    &exp,
			Iat:    &iat,
			Iss:    &iss,
			Sid:    &sid,
			Sub:    &aid,
			//Uid:    &uid,
			Scope:      &scope,
			Email:      &emptyStr,
			GivenName:  &emptyStr,
			Prefix:     &emptyStr,
			FamilyName: &emptyStr,
			Name:       &emptyStr,
		}
		expectStatusOK(ctx, response)

		if !assert.NoError(t, ctx.wrapper.IntrospectAccessToken(ctx.echoMock)) {
			t.Fail()
		}
	})
}
