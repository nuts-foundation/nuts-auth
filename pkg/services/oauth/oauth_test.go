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

package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/golang/mock/gomock"
	servicesMock "github.com/nuts-foundation/nuts-auth/mock/services"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	consentMock "github.com/nuts-foundation/nuts-consent-store/mock"
	pkg2 "github.com/nuts-foundation/nuts-consent-store/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/cert"
	"github.com/nuts-foundation/nuts-crypto/pkg/storage"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-crypto/test"
	cryptoMock "github.com/nuts-foundation/nuts-crypto/test/mock"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/nuts-foundation/nuts-go-test/io"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	registryTest "github.com/nuts-foundation/nuts-registry/test"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
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

	t.Run("missing client certificate", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(&db.Organization{Vendor: vendorID}, nil)
		ctx.cryptoMock.EXPECT().TrustStore().Return(testTrustStore{ca: vendorCA(t)})

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})

		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid TLS client certificate")
		}
	})

	t.Run("broken identity token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Times(2).Return(&db.Organization{Vendor: vendorID}, nil)
		ctx.cryptoMock.EXPECT().TrustStore().AnyTimes().Return(testTrustStore{ca: vendorCA(t)})
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any()).Return(nil, errors.New("identity validation failed"))

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken, ClientCert: clientCert(t)})

		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "identity validation failed")
		}
	})

	t.Run("JWT validity to long", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.ExpiresAt = time.Now().Add(10 * time.Second).Unix()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "JWT validity to long")
		}
	})

	t.Run("invalid identity token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any()).Return(&contract.VerificationResult{State: contract.Invalid}, nil)
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Times(2).Return(&db.Organization{Vendor: vendorID}, nil)
		ctx.cryptoMock.EXPECT().TrustStore().AnyTimes().Return(testTrustStore{ca: vendorCA(t)})

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken, ClientCert: clientCert(t)})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "identity validation failed")
		}
	})

	t.Run("valid - with legal base", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.contractClientMock.EXPECT().VerifyVP(gomock.Any()).Return(&contract.VerificationResult{State: contract.Valid, DisclosedAttributes: map[string]string{"name": "Henk de Vries"}}, nil)
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(&db.Organization{Vendor: vendorID}, nil)
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(&db.Organization{Vendor: vendorID}, nil)
		ctx.cryptoMock.EXPECT().TrustStore().AnyTimes().Return(testTrustStore{ca: vendorCA(t)})
		ctx.consentMock.EXPECT().QueryConsent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]pkg2.PatientConsent{{}}, nil)
		ctx.cryptoMock.EXPECT().SignJWT(gomock.Any(), gomock.Any()).Return("expectedAT", nil)

		tokenCtx := validContext()
		signToken(tokenCtx)

		response, err := ctx.oauthService.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: tokenCtx.rawJwtBearerToken, ClientCert: clientCert(t)})
		assert.Nil(t, err)
		if assert.NotNil(t, response) {
			assert.Equal(t, "expectedAT", response.AccessToken)
		}
	})
}

func TestService_validateIssuer(t *testing.T) {
	t.Run("invalid issuer format", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Issuer = "not a urn"

		err := ctx.oauthService.validateIssuer(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid jwt.issuer: invalid PartyID: not a urn")
		}
	})

	t.Run("unknown issuer", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(nil, db.ErrOrganizationNotFound)

		tokenCtx := validContext()

		err := ctx.oauthService.validateIssuer(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid jwt.issuer: organization not found")
		}
	})

	t.Run("invalid signing certificate", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(&db.Organization{Vendor: vendorID}, nil)
		ctx.cryptoMock.EXPECT().TrustStore().Return(testTrustStore{err: errors.New("x509 verify error")})

		tokenCtx := validContext()

		err := ctx.oauthService.validateIssuer(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "x509 verify error")
		}
	})

	t.Run("actor no sibling of x5c signing certificate", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		fakeVendor, _ := core.NewPartyID("q", "v")
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(&db.Organization{Vendor: fakeVendor}, nil)
		ctx.cryptoMock.EXPECT().TrustStore().Return(testTrustStore{ca: vendorCA(t)})

		tokenCtx := validContext()

		err := ctx.oauthService.validateIssuer(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "the signing certificate from the actor registry entry and the certificate from the x5c header do not share a common vendor CA")
		}
	})
}

func TestService_validateSubject(t *testing.T) {
	t.Run("invalid subject format", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.Subject = "not a urn"

		err := ctx.oauthService.validateSubject(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid jwt.subject: invalid PartyID: not a urn")
		}
	})

	t.Run("unknown subject", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(nil, db.ErrOrganizationNotFound)

		tokenCtx := validContext()

		err := ctx.oauthService.validateSubject(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid jwt.subject: organization not found")
		}
	})

	t.Run("no match for node vendorId", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		pId, _ := core.NewPartyID(vendorID.OID(), vendorID.Value() + "1")

		ctx.registryMock.EXPECT().OrganizationById(gomock.Any()).Return(&db.Organization{
			Vendor: pId,
		}, nil)

		tokenCtx := validContext()

		err := ctx.oauthService.validateSubject(tokenCtx)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "invalid jwt.subject: subject.vendor: urn:oid:1.3.6.1.4.1.54851.4:vendorId1 doesn't match with vendorID of this node: urn:oid:1.3.6.1.4.1.54851.4:vendorId")
		}
	})
}

// todo validate actor
// todo validate client cert

func TestService_validateLegalBase(t *testing.T) {
	t.Run("no legal base present", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.consentMock.EXPECT().QueryConsent(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return([]pkg2.PatientConsent{}, nil)

		tokenCtx := validContext()

		err := ctx.oauthService.validateLegalBase(tokenCtx.jwtBearerToken)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "subject scope requested but no legal base present")
		}
	})

	t.Run("valid - no legal base and no sid", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.SubjectID = nil

		err := ctx.oauthService.validateLegalBase(tokenCtx.jwtBearerToken)
		assert.NoError(t, err)

	})

	t.Run("valid - empty sid", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		sid := ""

		tokenCtx := validContext()
		tokenCtx.jwtBearerToken.SubjectID = &sid

		err := ctx.oauthService.validateLegalBase(tokenCtx.jwtBearerToken)
		assert.NoError(t, err)
	})
}

func TestOAuthService_parseAndValidateJwtBearerToken(t *testing.T) {
	ctx := createContext(t)
	defer ctx.ctrl.Finish()

	t.Run("malformed JWTs", func(t *testing.T) {
		tokenCtx := &validationContext{
			rawJwtBearerToken: "foo",
		}
		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerToken)
		assert.Equal(t, "token contains an invalid number of segments", err.Error())

		tokenCtx2 := &validationContext{
			rawJwtBearerToken: "123.456.787",
		}
		err = ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx2)
		assert.Nil(t, tokenCtx.jwtBearerToken)
		assert.Equal(t, "invalid character '×' looking for beginning of value", err.Error())
	})

	t.Run("wrong signing algorithm", func(t *testing.T) {
		// alg: HS256
		const invalidJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MDAwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjo0MDcwOTA4ODAwLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.2_4bxKKsVspQ4QxXRG8m2mOnLbl-fFgSkEq_h8N9sNE"
		tokenCtx := &validationContext{
			rawJwtBearerToken: invalidJwt,
		}
		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerToken)
		assert.Equal(t, "signing method HS256 is invalid", err.Error())
	})

	t.Run("missing x5c header", func(t *testing.T) {
		tokenCtx := validContext()
		signTokenWithHeader(tokenCtx, []string{})
		tokenCtx.jwtBearerToken = nil

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerToken)
		assert.Equal(t, "invalid x5c header", err.Error())
	})

	t.Run("x5c header to large", func(t *testing.T) {
		tokenCtx := validContext()
		signTokenWithHeader(tokenCtx, []string{"a", "b"})
		tokenCtx.jwtBearerToken = nil

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerToken)
		assert.Equal(t, "invalid x5c header", err.Error())
	})

	t.Run("x5c header wrong format", func(t *testing.T) {
		tokenCtx := validContext()
		signTokenWithHeader(tokenCtx, []string{"a"})
		tokenCtx.jwtBearerToken = nil

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, tokenCtx.jwtBearerToken)
		assert.Equal(t, "invalid x5c header: illegal base64 data at input byte 0", err.Error())
	})

	t.Run("valid token", func(t *testing.T) {
		tokenCtx := validContext()
		signToken(tokenCtx)

		err := ctx.oauthService.parseAndValidateJwtBearerToken(tokenCtx)
		assert.Nil(t, err)
		assert.Equal(t, "urn:oid:2.16.840.1.113883.2.4.6.1:actor", tokenCtx.jwtBearerToken.Issuer)

	})
}

func TestOAuthService_buildAccessToken(t *testing.T) {
	t.Run("missing subject", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		tokenCtx := &validationContext{
			contractVerificationResult: &contract.VerificationResult{State: contract.Valid},
			jwtBearerToken:             &services.NutsJwtBearerToken{},
		}

		token, err := ctx.oauthService.buildAccessToken(tokenCtx)
		assert.Empty(t, token)
		assert.EqualError(t, err, "could not build accessToken: subject is missing")
	})

	t.Run("build an access token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().SignJWT(gomock.Any(), gomock.Any()).Return("expectedAT", nil)

		tokenCtx := &validationContext{
			contractVerificationResult: &contract.VerificationResult{State: contract.Valid},
			jwtBearerToken:             &services.NutsJwtBearerToken{StandardClaims: jwt.StandardClaims{Subject: organizationID.String()}},
		}

		token, err := ctx.oauthService.buildAccessToken(tokenCtx)

		assert.Nil(t, err)
		assert.Equal(t, "expectedAT", token)
	})

	// todo some extra tests needed for claims generation
}

func TestOAuthService_CreateJwtBearerToken(t *testing.T) {
	sid := "789"
	usi := "irma identity token"
	request := services.CreateJwtBearerTokenRequest{
		Custodian:     otherOrganizationID.String(),
		Actor:         organizationID.String(),
		Subject:       &sid,
		IdentityToken: &usi,
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
			Subject:       &sid,
			IdentityToken: &usi,
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
	sid := "789"
	usi := "irma identity token"

	t.Run("ok", func(t *testing.T) {
		request := services.CreateJwtBearerTokenRequest{
			Custodian:     otherOrganizationID.String(),
			Actor:         organizationID.String(),
			Subject:       &sid,
			IdentityToken: &usi,
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
		assert.Equal(t, request.IdentityToken, claims.UserIdentity)
		assert.Equal(t, request.Subject, claims.SubjectID)
	})
}

func TestOAuthService_IntrospectAccessToken(t *testing.T) {

	t.Run("validate access token", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(oauthKeyEntity).Return(true)
		ctx.cryptoMock.EXPECT().GetPrivateKey(oauthKeyEntity).Return(key, nil)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		claims, err := ctx.oauthService.IntrospectAccessToken(tokenCtx.rawJwtBearerToken)
		if !assert.NoError(t, err) || !assert.NotNil(t, claims) {
			t.FailNow()
		}
	})

	t.Run("missing key", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.cryptoMock.EXPECT().PrivateKeyExists(oauthKeyEntity).Return(false)

		// First build an access token
		tokenCtx := validContext()
		signToken(tokenCtx)

		// Then validate it
		_, err := ctx.oauthService.IntrospectAccessToken(tokenCtx.rawJwtBearerToken)
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

func clientCert(t *testing.T) string {
	c, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatal(err)
	}
	return cert.CertificateToPEM(c)
}

func validContext() *validationContext {
	sid := "subject"
	usi := base64.StdEncoding.EncodeToString([]byte("irma identity token"))
	token := services.NutsJwtBearerToken{
		StandardClaims: jwt.StandardClaims{
			Audience:  "endpoint",
			ExpiresAt: time.Now().Add(5 * time.Second).Unix(),
			Id:        "a005e81c-6749-4967-b01c-495228fcafb4",
			IssuedAt:  time.Now().Unix(),
			Issuer:    "urn:oid:2.16.840.1.113883.2.4.6.1:actor",
			NotBefore: 0,
			Subject:   "urn:oid:2.16.840.1.113883.2.4.6.1:custodian",
		},
		UserIdentity: &usi,
		SubjectID:    &sid,
	}
	return &validationContext{
		jwtBearerToken: &token,
	}
}

func signToken(context *validationContext) {
	certificate, _ := x509.ParseCertificate(certBytes)
	chain := cert.MarshalX509CertChain([]*x509.Certificate{certificate})

	// Sign and get the complete encoded token as a string using the secret
	signTokenWithHeader(context, chain)
}

func signTokenWithHeader(context *validationContext, chain []string) {
	var keyVals map[string]interface{}
	inrec, _ := json.Marshal(context.jwtBearerToken)
	if err := json.Unmarshal(inrec, &keyVals); err != nil {
		return
	}

	c := jwt.MapClaims{}
	for k, v := range keyVals {
		c[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	token.Header["x5c"] = chain

	// Sign and get the complete encoded token as a string using the secret
	context.rawJwtBearerToken, _ = token.SignedString(key)
}

type testContext struct {
	ctrl               *gomock.Controller
	cryptoMock         *cryptoMock.MockClient
	registryMock       *registryMock.MockRegistryClient
	contractClientMock *servicesMock.MockContractClient
	consentMock        *consentMock.MockConsentStoreClient
	oauthService       *service
}

var createContext = func(t *testing.T) *testContext {
	os.Setenv("NUTS_IDENTITY", vendorID.String())
	if err := core.NutsConfig().Load(&cobra.Command{}); err != nil {
		panic(err)
	}

	ctrl := gomock.NewController(t)
	cryptoMock := cryptoMock.NewMockClient(ctrl)
	registryMock := registryMock.NewMockRegistryClient(ctrl)
	contractClientMock := servicesMock.NewMockContractClient(ctrl)
	consentMock := consentMock.NewMockConsentStoreClient(ctrl)
	return &testContext{
		ctrl:               ctrl,
		cryptoMock:         cryptoMock,
		registryMock:       registryMock,
		contractClientMock: contractClientMock,
		consentMock:        consentMock,
		oauthService: &service{
			vendorID:       vendorID,
			crypto:         cryptoMock,
			registry:       registryMock,
			oauthKeyEntity: oauthKeyEntity,
			consent:        consentMock,
			contractClient: contractClientMock,
		},
	}
}

type testTrustStore struct {
	err error
	ca  *x509.Certificate
}

func (tss testTrustStore) Verify(certificate *x509.Certificate, t time.Time) error {
	return tss.err
}

func (tss testTrustStore) VerifiedChain(certificate *x509.Certificate, t time.Time) ([][]*x509.Certificate, error) {
	if tss.err != nil {
		return nil, tss.err
	}

	return [][]*x509.Certificate{{tss.ca, tss.ca}}, nil
}

func (tss testTrustStore) Roots() ([]*x509.Certificate, *x509.CertPool) {
	panic("implement me")
}

func (tss testTrustStore) Intermediates() ([]*x509.Certificate, *x509.CertPool) {
	panic("implement me")
}

func (tss testTrustStore) AddCertificate(certificate *x509.Certificate) error {
	panic("implement me")
}

func (tss testTrustStore) GetRoots(t time.Time) []*x509.Certificate {
	panic("implement me")
}

func (tss testTrustStore) GetCertificates(i [][]*x509.Certificate, t time.Time, b bool) [][]*x509.Certificate {
	panic("implement me")
}

func vendorCA(t *testing.T) *x509.Certificate {
	dir := io.TestDirectory(t)
	backend, _ := storage.NewFileSystemBackend(dir)
	crypto := pkg.Crypto{
		Storage: backend,
		Config:  pkg.TestCryptoConfig(dir),
	}
	crypto.Config.Keysize = 1024

	c, _ := crypto.SelfSignVendorCACertificate("test")

	return c
}
