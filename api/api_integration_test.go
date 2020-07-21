package api

import (
	"encoding/base64"
	"encoding/json"
	pkg2 "github.com/nuts-foundation/nuts-network/pkg"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v4"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/nuts-foundation/nuts-registry/pkg/events/domain"
	"github.com/spf13/cobra"

	irma "github.com/privacybydesign/irmago"

	"github.com/nuts-foundation/nuts-auth/testdata"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-auth/pkg"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-go-core/mock"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
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

	emptyRegistry := func(t *testing.T, path string) {
		t.Helper()
		files, err := filepath.Glob(filepath.Join(path, "*"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if err := os.RemoveAll(file); err != nil {
				t.Fatal(err)
			}
		}
	}

	validContracts := map[pkg.Language]map[pkg.ContractType]map[pkg.Version]*pkg.ContractTemplate{
		"NL": {"BehandelaarLogin": {
			"v1": &pkg.ContractTemplate{
				Type:               "BehandelaarLogin",
				Version:            "v1",
				Language:           "NL",
				SignerAttributes:   []string{"gemeente.personalData.fullname", "gemeente.personalData.firstnames", "gemeente.personalData.prefix", "gemeente.personalData.familyname"},
				Template:           `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan {{acting_party}} om namens {{legal_entity}} en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van {{valid_from}} tot {{valid_to}}.`,
				TemplateAttributes: []string{"acting_party", "legal_entity", "valid_from", "valid_to"},
				Regexp:             `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan (.+) om namens (.+) en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van (.+) tot (.+).`,
			},
		}}}

	createContext := func(t *testing.T) *IntegrationTestContext {
		os.Setenv("NUTS_IDENTITY", "oid:123")
		core.NutsConfig().Load(&cobra.Command{})
		t.Helper()
		ctrl := gomock.NewController(t)

		auth := &pkg.Auth{
			Config:                 pkg.AuthConfig{},
			ContractSessionHandler: nil,
			ContractValidator:      nil,
			AccessTokenHandler:     nil,
			ValidContracts:         validContracts,
		}

		registryPath := "../testdata/registry"
		emptyRegistry(t, registryPath)

		cryptoInstance = crypto.CryptoInstance()
		cryptoInstance.Config.Fspath = "../testdata/tmp"
		cryptoInstance.Configure()

		networkInstance := pkg2.NetworkInstance()
		networkInstance.Config.StorageConnectionString = ":memory:"
		networkInstance.Configure()

		r := registry.RegistryInstance()
		r.Config.Mode = "server"
		r.Config.Datadir = registryPath
		r.Config.SyncMode = "fs"
		r.Config.OrganisationCertificateValidity = 1
		r.Config.VendorCACertificateValidity = 1
		if err := r.Configure(); !assert.NoError(t, err) {
			t.FailNow()
		}

		// Register a vendor
		_, _ = r.RegisterVendor("Test Vendor", domain.HealthcareDomain)

		// Add Organization to registry
		orgName := "Zorggroep Nuts"
		if _, err := r.VendorClaim(OrganizationID, orgName, nil); err != nil {
			t.Fatal(err)
		}

		// Generate keys for OtherOrganization
		if _, err := r.VendorClaim(OtherOrganizationID, "verpleeghuis De nootjes", nil); err != nil {
			t.Fatal(err)
		}

		vendorIdentifierFromHeader = func(ctx echo.Context) string {
			return "Demo EHR"
		}

		irmaConfig, err := pkg.GetIrmaConfig(pkg.AuthConfig{
			IrmaConfigPath:            "../testdata/irma",
			SkipAutoUpdateIrmaSchemas: true,
		})
		if err != nil {
			t.Fatal(err)
		}
		validator := pkg.DefaultValidator{
			Registry:       r,
			Crypto:         cryptoInstance,
			IrmaConfig:     irmaConfig,
			ValidContracts: validContracts,
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
		t.Helper()
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
		if !assert.NoError(t, err) {
			t.FailNow()
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
