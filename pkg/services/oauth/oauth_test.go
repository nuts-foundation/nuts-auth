package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	servicesMock "github.com/nuts-foundation/nuts-auth/mock/services"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-crypto/test"
	cryptoMock "github.com/nuts-foundation/nuts-crypto/test/mock"
	core "github.com/nuts-foundation/nuts-go-core"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	registryTest "github.com/nuts-foundation/nuts-registry/test"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

func TestAuth_CreateAccessToken(t *testing.T) {
	t.Run("invalid jwt", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "jwt bearer token validation failed")
		}
	})

	t.Run("invalid identity", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.contractValidatorMock.EXPECT().ValidateJwt("authToken", "").Return(nil, errors.New("identity validation failed"))

		token := validBearerToken()
		JWT := signToken(token)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: JWT})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "identity validation failed")
		}
	})

	t.Run("it creates a token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.contractValidatorMock.EXPECT().ValidateJwt("authToken", "").Return(&services.ContractValidationResult{ValidationResult: services.Valid, DisclosedAttributes: map[string]string{"name": "Henk de Vries"}}, nil)
		ctx.cryptoMock.EXPECT().SignJWT(gomock.Any(), gomock.Any()).Return("expectedAT", nil)

		token := validBearerToken()
		JWT := signToken(token)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: JWT})
		assert.Nil(t, err)
		if assert.NotNil(t, response) {
			assert.Equal(t, "expectedAT", response.AccessToken)
		}
	})
}

func TestOAuthService_parseAndValidateJwtBearerToken(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("malformed access tokens", func(t *testing.T) {
		response, err := ctx.oauthService.parseAndValidateJwtBearerToken("foo")
		assert.Nil(t, response)
		assert.Equal(t, "token contains an invalid number of segments", err.Error())

		response, err = ctx.oauthService.parseAndValidateJwtBearerToken("123.456.787")
		assert.Nil(t, response)
		assert.Equal(t, "invalid character '×' looking for beginning of value", err.Error())
	})

	t.Run("wrong signing algorithm", func(t *testing.T) {
		// alg: HS256
		const invalidJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MDAwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjo0MDcwOTA4ODAwLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.2_4bxKKsVspQ4QxXRG8m2mOnLbl-fFgSkEq_h8N9sNE"
		response, err := ctx.oauthService.parseAndValidateJwtBearerToken(invalidJwt)
		assert.Nil(t, response)
		assert.Equal(t, "signing method HS256 is invalid", err.Error())
	})

	t.Run("valid token", func(t *testing.T) {
		token := validBearerToken()
		jwt := signToken(token)

		response, err := ctx.oauthService.parseAndValidateJwtBearerToken(jwt)
		assert.Nil(t, err)
		assert.Equal(t, "actor", response.Issuer)
	})
}

func TestOAuthService_buildAccessToken(t *testing.T) {
	t.Run("missing subject", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		claims := &services.NutsJwtBearerToken{}
		identityValidationResult := &services.ContractValidationResult{ValidationResult: services.Valid}

		token, err := ctx.oauthService.buildAccessToken(claims, identityValidationResult)
		assert.Empty(t, token)
		assert.EqualError(t, err, "could not build accessToken: subject is missing")
	})

	t.Run("build an access token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().SignJWT(gomock.Any(), gomock.Any()).Return("expectedAT", nil)

		claims := &services.NutsJwtBearerToken{StandardClaims: jwt.StandardClaims{Subject: organizationID.String()}}
		identityValidationResult := &services.ContractValidationResult{ValidationResult: services.Valid}
		token, err := ctx.oauthService.buildAccessToken(claims, identityValidationResult)

		assert.Nil(t, err)
		assert.Equal(t, "expectedAT", token)
	})

	// todo some extra tests needed for claims generation
}

func TestOAuthService_CreateJwtBearerToken(t *testing.T) {
	request := services.CreateJwtBearerTokenRequest{
		Custodian:     otherOrganizationID.String(),
		Actor:         organizationID.String(),
		Subject:       "789",
		IdentityToken: "irma identity token",
	}

	t.Run("create a JwtBearerToken", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().SignJWTRFC003(gomock.Any()).Return("token", nil)
		ctx.registryMock.EXPECT().EndpointsByOrganizationAndType(gomock.Any(), gomock.Any()).Return([]db.Endpoint{{Identifier: "id"}}, nil)

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		if !assert.Nil(t, err) || !assert.NotEmpty(t, token.BearerToken) {
			t.FailNow()
		}
		assert.Equal(t, "token", token.BearerToken)
	})

	t.Run("custodian without endpoint", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.registryMock.EXPECT().EndpointsByOrganizationAndType(gomock.Any(), gomock.Any()).Return([]db.Endpoint{}, nil)

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		assert.Empty(t, token)
		assert.True(t, errors.Is(err, errIncorrectNumberOfEndpoints))
	})

	t.Run("request without custodian", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		request := services.CreateJwtBearerTokenRequest{
			Actor:         organizationID.String(),
			Subject:       "789",
			IdentityToken: "irma identity token",
		}

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		assert.Empty(t, token)
		assert.NotNil(t, err)
	})

	t.Run("signing error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().SignJWTRFC003(gomock.Any()).Return("", errors.New("boom!"))
		ctx.registryMock.EXPECT().EndpointsByOrganizationAndType(gomock.Any(), gomock.Any()).Return([]db.Endpoint{{Identifier: "id"}}, nil)

		token, err := ctx.oauthService.CreateJwtBearerToken(request)

		assert.Error(t, err)
		assert.Empty(t, token)
	})

}

func Test_claimsFromRequest(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("ok", func(t *testing.T) {
		request := services.CreateJwtBearerTokenRequest{
			Custodian:     otherOrganizationID.String(),
			Actor:         organizationID.String(),
			Subject:       "789",
			IdentityToken: "irma identity token",
		}
		audience := "aud"
		timeFunc = func() time.Time {
			return time.Unix(10, 0)
		}
		defer func() {
			timeFunc = time.Now
		}()

		claims := claimsFromRequest(request, audience)

		assert.Equal(t, audience, claims.Audience)
		assert.Equal(t, int64(15), claims.ExpiresAt)
		assert.Equal(t, int64(10), claims.IssuedAt)
		assert.Equal(t, request.Actor, claims.Issuer)
		assert.Equal(t, int64(0), claims.NotBefore)
		assert.Equal(t, request.Custodian, claims.Subject)
		assert.Equal(t, request.IdentityToken, claims.AuthTokenContainer)
		assert.Equal(t, request.Subject, claims.SubjectID)
	})
}

func TestOAuthService_validateAccessToken(t *testing.T) {

	t.Run("validate access token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(oauthKeyEntity).Return(true)
		ctx.cryptoMock.EXPECT().GetPrivateKey(oauthKeyEntity).Return(key, nil)

		// First build an access token
		token := validBearerToken()
		jwt := signToken(token)

		// Then validate it
		claims, err := ctx.oauthService.parseAndValidateAccessToken(jwt)
		if !assert.NoError(t, err) || !assert.NotNil(t, claims) {
			t.FailNow()
		}
	})

	t.Run("missing key", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(oauthKeyEntity).Return(false)

		// First build an access token
		token := validBearerToken()
		jwt := signToken(token)

		// Then validate it
		_, err := ctx.oauthService.parseAndValidateAccessToken(jwt)
		assert.Error(t, err)
	})
}

func TestAuth_Configure(t *testing.T) {
	t.Run("ok - config valid", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(oauthKeyEntity).Return(true)

		assert.NoError(t, ctx.oauthService.Configure())
	})

	t.Run("missing private key", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(oauthKeyEntity).Return(false)
		ctx.cryptoMock.EXPECT().GenerateKeyPair(oauthKeyEntity, false)

		assert.NoError(t, ctx.oauthService.Configure())
	})
}

var organizationID = registryTest.OrganizationID("00000001")
var otherOrganizationID = registryTest.OrganizationID("00000002")

var vendorID, _ = core.ParsePartyID("urn:oid:1.3.6.1.4.1.54851.4:vendorId")
var key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
var certBytes = test.GenerateCertificate(time.Now(), 2, key)
var oauthKeyEntity = cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: vendorID.String()}).WithQualifier(oauthKeyQualifier)

func validBearerToken() services.NutsJwtBearerToken {
	return services.NutsJwtBearerToken{
		StandardClaims: jwt.StandardClaims{
			Audience:  "endpoint",
			ExpiresAt: time.Now().Add(5 * time.Second).Unix(),
			Id:        "a005e81c-6749-4967-b01c-495228fcafb4",
			IssuedAt:  time.Now().Unix(),
			Issuer:    "actor",
			NotBefore: 0,
			Subject:   "custodian",
		},
		AuthTokenContainer: "authToken",
		SubjectID:          "subject",
	}
}

func signToken(jwtBearerToken services.NutsJwtBearerToken) string {
	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(jwtBearerToken)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return ""
	}

	c := jwt.MapClaims{}
	for k, v := range keyVals {
		c[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	certificate, _ := x509.ParseCertificate(certBytes)
	chain := cert.MarshalX509CertChain([]*x509.Certificate{certificate})
	token.Header["x5c"] = chain

	// Sign and get the complete encoded token as a string using the secret
	tokenString, _ := token.SignedString(key)
	return tokenString
}

type testContext struct {
	ctrl                  *gomock.Controller
	cryptoMock            *cryptoMock.MockClient
	registryMock          *registryMock.MockRegistryClient
	contractValidatorMock *servicesMock.MockContractValidator
	oauthService          *service
}

var createContext = func(t *testing.T) *testContext {
	ctrl := gomock.NewController(t)
	cryptoMock := cryptoMock.NewMockClient(ctrl)
	registryMock := registryMock.NewMockRegistryClient(ctrl)
	contractValidatorMock := servicesMock.NewMockContractValidator(ctrl)
	return &testContext{
		ctrl:                  ctrl,
		cryptoMock:            cryptoMock,
		registryMock:          registryMock,
		contractValidatorMock: contractValidatorMock,
		oauthService: &service{
			vendorID:          vendorID,
			crypto:            cryptoMock,
			registry:          registryMock,
			oauthKeyEntity:    oauthKeyEntity,
			contractValidator: contractValidatorMock,
		},
	}
}
