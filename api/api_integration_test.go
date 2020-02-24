package api

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/labstack/echo/v4"

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
	const OtherOrganizationID = "urn:oid:2.16.840.1.113883.2.4.6.1:00000002"

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
		event, _ := events.CreateEvent(events.RegisterVendor, events.RegisterVendorEvent{Identifier: "oid:123", Name: "Awesomesoft"})
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
		event, _ = events.CreateEvent(events.VendorClaim, events.VendorClaimEvent{
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
		event, _ = events.CreateEvent(events.VendorClaim, events.VendorClaimEvent{
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

		// Add oauth endpoint to OtherOrganization
		event, _ = events.CreateEvent(events.RegisterEndpoint, events.RegisterEndpointEvent{
			Organization: OtherOrganizationID,
			URL:          "tcp://127.0.0.1:1234",
			EndpointType: pkg.SsoEndpointType,
			Identifier:   "1f7d4ea7-c1cf-4c14-ba23-7e1fddc31ad1",
			Status:       "active",
			Version:      "0.1",
		})
		if err := r.EventSystem.PublishEvent(event); err != nil {
			panic(err)
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

	// This is a full integration test for the OAuth JWT bearer flow. Only the identity token part is mocked.
	// Organization wants to make a request to OtherOrganization. It builds an JWT Bearer token, request the access token.
	// OtherOrganization then inspect the access token.
	t.Run("complete flow from identity token to access token introspection", func(t *testing.T) {

		// use a fake time so the identity token is valid
		testTime, err := time.Parse(time.RFC3339, "2020-02-19T16:38:45+01:00")
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

			// build a request to create the jwt bearer token
			jwtBearerTokenRequest := CreateJwtBearerTokenRequest{
				Actor:     OrganizationID,
				Custodian: OtherOrganizationID,
				Identity:  idToken,
				Scope:     "nuts-sso",
				Subject:   "99999990",
			}
			bindPostBody(ctx, jwtBearerTokenRequest)

			// store the response for later use
			jwtBearerTokenResponse := &JwtBearerTokenResponse{}
			expectStatusOK(ctx, JwtBearerTokenResponse{}, jwtBearerTokenResponse)

			if !assert.NoError(t, ctx.wrapper.CreateJwtBearerToken(ctx.echoMock)) {
				t.FailNow()
			}

			// make sure the echo mock returns the correct form values
			ctx.echoMock.EXPECT().FormValue("grant_type").Return(pkg.JwtBearerGrantType)
			ctx.echoMock.EXPECT().FormValue("assertion").Return(jwtBearerTokenResponse.BearerToken)

			// store the response for later use
			accessTokenResponse := &AccessTokenResponse{}
			expectStatusOK(ctx, AccessTokenResponse{}, accessTokenResponse)

			if !assert.NoError(t, ctx.wrapper.CreateAccessToken(ctx.echoMock)) {
				t.FailNow()
			}

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
			assert.Equal(t, "nuts-sso", keyVals["scope"].(string))
		})
	})
}
