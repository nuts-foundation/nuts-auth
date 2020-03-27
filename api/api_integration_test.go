package api

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	"github.com/nuts-foundation/nuts-registry/pkg/events/domain"

	irma "github.com/privacybydesign/irmago"

	"github.com/nuts-foundation/nuts-auth/testdata"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-auth/pkg"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	"github.com/nuts-foundation/nuts-go-core/mock"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/events"
	"github.com/stretchr/testify/assert"
)

var cryptoInstance *crypto.Crypto

func Test_Integration(t *testing.T) {
	const OrganizationID = "urn:oid:2.16.840.1.113883.2.4.6.1:00000003"
	const OtherOrganizationID = "urn:oid:2.16.840.1.113883.2.4.6.1:00000004"

	type IntegrationTestContext struct {
		wrapper  Wrapper
		ctrl     *gomock.Controller
		echoMock *mock.MockContext
	}

	createContext := func(t *testing.T) *IntegrationTestContext {
		ctrl := gomock.NewController(t)

		auth := &pkg.Auth{
			Config:                 pkg.AuthConfig{},
			ContractSessionHandler: nil,
			ContractValidator:      nil,
			AccessTokenHandler:     nil,
		}

		r := registry.RegistryInstance()
		r.Config.Mode = "server"
		r.Config.Datadir = "../testdata/registry"
		r.Config.SyncMode = "fs"
		if err := r.Configure(); err != nil {
			panic(err)
		}

		// Register a vendor
		event := events.CreateEvent(domain.RegisterVendor, domain.RegisterVendorEvent{Identifier: "oid:123", Name: "Awesomesoft"})
		if err := r.EventSystem.PublishEvent(event); err != nil {
			panic(err)
		}

		cryptoInstance = &crypto.Crypto{
			Config: crypto.CryptoConfig{
				Keysize: types.ConfigKeySizeDefault,
				Fspath:  "../testdata/tmp",
			},
		}
		if err := cryptoInstance.Configure(); err != nil {
			panic(err)
		}

		// Generate keys for Organization
		le := types.LegalEntity{URI: OrganizationID}
		_ = cryptoInstance.GenerateKeyPairFor(le)
		pub, _ := cryptoInstance.PublicKeyInJWK(le)

		// Add Organization to registry
		event = events.CreateEvent(domain.VendorClaim, domain.VendorClaimEvent{
			VendorIdentifier: "oid:123",
			OrgIdentifier:    OrganizationID,
			OrgName:          "Zorggroep Nuts",
			OrgKeys:          []interface{}{pub},
		})
		if err := r.EventSystem.PublishEvent(event); err != nil {
			panic(err)
		}

		// Generate keys for OtherOrganization
		le = types.LegalEntity{URI: OtherOrganizationID}
		_ = cryptoInstance.GenerateKeyPairFor(le)
		pub, _ = cryptoInstance.PublicKeyInJWK(le)

		// Add Organization to registry
		event = events.CreateEvent(domain.VendorClaim, domain.VendorClaimEvent{
			VendorIdentifier: "oid:123",
			OrgIdentifier:    OtherOrganizationID,
			OrgName:          "verpleeghuis De nootjes",
			OrgKeys:          []interface{}{pub},
		})
		if err := r.EventSystem.PublishEvent(event); err != nil {
			panic(err)
		}

		vendorIdentifierFromHeader = func(ctx echo.Context) string {
			return "Demo EHR"
		}

		validator := pkg.DefaultValidator{
			//IrmaServer: &pkg.DefaultIrmaClient{I: GetIrmaServer(auth.Config)},
			//irmaConfig: GetIrmaConfig(auth.Config),
			Registry: r,
			Crypto:   cryptoInstance,
			IrmaConfig: pkg.GetIrmaConfig(pkg.AuthConfig{
				IrmaConfigPath:            "../testdata/irma",
				SkipAutoUpdateIrmaSchemas: true,
			}),
		}
		auth.ContractSessionHandler = validator
		auth.ContractValidator = validator
		auth.AccessTokenHandler = validator

		return &IntegrationTestContext{
			ctrl:     ctrl,
			wrapper:  Wrapper{Auth: auth},
			echoMock: mock.NewMockContext(ctrl),
		}
	}

	bindPostBody := func(ctx *IntegrationTestContext, body interface{}) {
		jsonData, _ := json.Marshal(body)
		ctx.echoMock.EXPECT().Bind(gomock.Any()).Do(func(f interface{}) {
			_ = json.Unmarshal(jsonData, f)
		})
	}

	expectStatusOK := func(ctx *IntegrationTestContext, respType interface{}, lastResponse interface{}) {
		ctx.echoMock.EXPECT().JSON(http.StatusOK, gomock.AssignableToTypeOf(respType)).Do(func(status int, response interface{}) {
			//lastResponse = &response
			p := reflect.ValueOf(lastResponse).Elem()
			val := reflect.ValueOf(response)
			p.Set(val)
		})
	}

	// Set the pkg.NowFunc to a temporary one to return a fake time. This makes it convenient to use stored test contracts.
	fakeTime := func(t *testing.T, newTime time.Time, f func(t *testing.T)) {
		oldFunc := pkg.NowFunc

		pkg.NowFunc = func() time.Time {
			return newTime
		}
		defer func() {
			pkg.NowFunc = oldFunc
		}()

		f(t)
	}

	printTokenConents := func(t *testing.T, tokenDesc, token string) {
		t.Helper()
		tokenBody := strings.Split(token, ".")[1]
		decodedBody, _ := base64.StdEncoding.DecodeString(tokenBody)
		t.Logf("type: %s, %s", tokenDesc, string(decodedBody))
	}

	// This is a full integration test for the OAuth JWT bearer flow. Only the identity token part is mocked.
	// Organization wants to make a request to OtherOrganization. It builds an JWT Bearer token, request the access token.
	// OtherOrganization then inspect the access token.
	t.Run("complete flow from identity token to access token introspection", func(t *testing.T) {

		// use a fake time so the identity token is valid
		testTime, err := time.Parse(time.RFC3339, "2020-02-24T16:38:45+01:00")
		if err != nil {
			panic(err)
		}
		fakeTime(t, testTime, func(t *testing.T) {

			ctx := createContext(t)

			// create an id token from a valid irma contract
			defaultValidator := pkg.DefaultValidator{Crypto: cryptoInstance}
			signedIrmaContract := irma.SignedMessage{}
			_ = json.Unmarshal([]byte(testdata.ValidIrmaContract2), &signedIrmaContract)
			contract := pkg.SignedIrmaContract{IrmaContract: signedIrmaContract}
			idToken, err := defaultValidator.CreateIdentityTokenFromIrmaContract(&contract, OrganizationID)
			if !assert.NoError(t, err) {
				t.FailNow()
			}
			subjectBsn := "99999990"

			// build a request to create the jwt bearer token
			jwtBearerTokenRequest := CreateJwtBearerTokenRequest{
				Actor:     OrganizationID,
				Custodian: OtherOrganizationID,
				Identity:  idToken,
				Scope:     "nuts-sso",
				Subject:   subjectBsn,
			}
			bindPostBody(ctx, jwtBearerTokenRequest)

			// store the response for later use
			jwtBearerTokenResponse := &JwtBearerTokenResponse{}
			expectStatusOK(ctx, JwtBearerTokenResponse{}, jwtBearerTokenResponse)

			if !assert.NoError(t, ctx.wrapper.CreateJwtBearerToken(ctx.echoMock)) {
				t.FailNow()
			}

			printTokenConents(t, "jwtBearerToken", jwtBearerTokenResponse.BearerToken)

			// make sure the echo mock returns the correct form values
			ctx.echoMock.EXPECT().FormValue("grant_type").Return(pkg.JwtBearerGrantType)
			ctx.echoMock.EXPECT().FormValue("assertion").Return(jwtBearerTokenResponse.BearerToken)

			// store the response for later use
			accessTokenResponse := &AccessTokenResponse{}
			expectStatusOK(ctx, AccessTokenResponse{}, accessTokenResponse)

			if !assert.NoError(t, ctx.wrapper.CreateAccessToken(ctx.echoMock)) {
				t.FailNow()
			}
			printTokenConents(t, "accessToken", accessTokenResponse.AccessToken)

			// make sure the echo mock returns the correct form value
			ctx.echoMock.EXPECT().FormValue("token").Return(accessTokenResponse.AccessToken)

			tokenIntrospectionResult := TokenIntrospectionResponse{}
			expectStatusOK(ctx, TokenIntrospectionResponse{}, &tokenIntrospectionResult)

			if !assert.NoError(t, ctx.wrapper.IntrospectAccessToken(ctx.echoMock)) {
				t.FailNow()
			}

			// Print the returned json document for visual inspection
			jsonResult, _ := json.Marshal(tokenIntrospectionResult)
			t.Log(string(jsonResult))

			// make the jsonn document easy to inspect by converting it to a key value map
			keyVals := map[string]interface{}{}
			_ = json.Unmarshal(jsonResult, &keyVals)

			// check the results
			assert.True(t, keyVals["active"].(bool))
			assert.Equal(t, OtherOrganizationID, keyVals["iss"].(string))
			assert.Equal(t, OrganizationID, keyVals["sub"].(string))
			assert.Equal(t, subjectBsn, keyVals["sid"].(string))
			assert.Equal(t, "nuts-sso", keyVals["scope"].(string))
			assert.Equal(t, "Bruijn", keyVals["family_name"].(string))
			assert.Equal(t, "de", keyVals["prefix"].(string))
			assert.Equal(t, "Willeke", keyVals["given_name"].(string))
			assert.Equal(t, "Willeke de Bruijn", keyVals["name"].(string))
		})
	})
}
