package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	irmaService "github.com/nuts-foundation/nuts-auth/pkg/services/irma"
	pkg2 "github.com/nuts-foundation/nuts-consent-store/pkg"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	testIo "github.com/nuts-foundation/nuts-go-test/io"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/sirupsen/logrus"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"

	test2 "github.com/nuts-foundation/nuts-auth/test"
	"github.com/nuts-foundation/nuts-registry/test"

	"github.com/labstack/echo/v4"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/spf13/cobra"

	irma "github.com/privacybydesign/irmago"

	"github.com/nuts-foundation/nuts-auth/testdata"

	"github.com/golang/mock/gomock"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-go-core/mock"
	"github.com/stretchr/testify/assert"
)

var organizationID = test.OrganizationID("00000003")
var otherOrganizationID = test.OrganizationID("00000004")
var subjectBsn, _ = core.NewPartyID("2.16.840.1.113883.2.4.6.3", "99999990")

// todo this test requires access to internals of other packages. Without this test some fields could be made private.
func Test_Integration(t *testing.T) {

	type IntegrationTestContext struct {
		auth     *pkg.Auth
		wrapper  Wrapper
		ctrl     *gomock.Controller
		echoMock *mock.MockContext
	}

	contract.StandardContractTemplates = map[contract.Language]map[contract.Type]map[contract.Version]*contract.Template{
		"NL": {"BehandelaarLogin": {
			"v1": &contract.Template{
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
		os.Setenv("NUTS_IDENTITY", test.VendorID("123").String())
		core.NutsConfig().Load(&cobra.Command{})
		t.Helper()
		ctrl := gomock.NewController(t)

		auth := newTestAuthInstance(t)

		// Register a vendor
		test2.RegisterVendor(t, "Awesomesoft", auth.Crypto, auth.Registry)

		// Add Organization to registry
		orgName := "Zorggroep Nuts"
		if _, err := auth.Registry.VendorClaim(organizationID, orgName, nil); err != nil {
			t.Fatal(err)
		}

		// Generate keys for OtherOrganization
		if _, err := auth.Registry.VendorClaim(otherOrganizationID, "verpleeghuis De nootjes", nil); err != nil {
			t.Fatal(err)
		}

		if _, err := auth.Registry.RegisterEndpoint(otherOrganizationID, "e-1", "url", "oauth", "active", nil); err != nil {
			t.Fatal(err)
		}

		vendorIdentifierFromHeader = func(ctx echo.Context) string {
			return "Demo EHR"
		}

		return &IntegrationTestContext{
			auth:     auth,
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
		oldFunc := contract.NowFunc

		contract.NowFunc = func() time.Time {
			return newTime
		}
		defer func() {
			contract.NowFunc = oldFunc
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
			defaultValidator := irmaService.IrmaService{Crypto: ctx.auth.Crypto}
			signedIrmaContract := irma.SignedMessage{}
			_ = json.Unmarshal([]byte(testdata.ValidIrmaContract2), &signedIrmaContract)
			contract := irmaService.SignedIrmaContract{IrmaContract: signedIrmaContract}
			idToken, err := defaultValidator.CreateIdentityTokenFromIrmaContract(&contract, organizationID)
			if !assert.NoError(t, err) {
				t.FailNow()
			}

			// build a request to create the jwt bearer token
			jwtBearerTokenRequest := CreateJwtBearerTokenRequest{
				Actor:     organizationID.String(),
				Custodian: otherOrganizationID.String(),
				Identity:  idToken,
				Scope:     "nuts-sso",
				Subject:   subjectBsn.String(),
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
			assert.Equal(t, otherOrganizationID.String(), keyVals["iss"].(string))
			assert.Equal(t, organizationID.String(), keyVals["sub"].(string))
			assert.Equal(t, subjectBsn.String(), keyVals["sid"].(string))
			assert.Equal(t, "Bruijn", keyVals["family_name"].(string))
			assert.Equal(t, "de", keyVals["prefix"].(string))
			assert.Equal(t, "Willeke", keyVals["given_name"].(string))
			assert.Equal(t, "Willeke de Bruijn", keyVals["name"].(string))
		})
	})
}

// NewTestAuthInstance returns a fully configured Auth instance
func newTestAuthInstance(t *testing.T) *pkg.Auth {
	testDirectory := testIo.TestDirectory(t)

	// init consent store in server mode
	cs := pkg2.ConsentStoreInstance()
	cs.Config.Connectionstring = fmt.Sprintf("file://%s/consent.db", testDirectory)
	if err := cs.Configure(); err != nil {
		logrus.Fatal(err)
	}
	if err := cs.Start(); err != nil {
		logrus.Fatal(err)
	}
	if err := cs.RecordConsent(context.Background(), []pkg2.PatientConsent{
		{
			ID:        "patient-uuid",
			Actor:     organizationID.String(),
			Custodian: otherOrganizationID.String(),
			Records: []pkg2.ConsentRecord{
				{
					ValidFrom: time.Now(),
					Hash:      "hash",
					Version:   0,
					UUID:      "uuid",
					DataClasses: []pkg2.DataClass{
						{
							Code: "test",
						},
					},
				},
			},
			Subject: subjectBsn.String(),
		},
	}); err != nil {
		logrus.Fatal(err)
	}

	config := pkg.DefaultAuthConfig()
	config.SkipAutoUpdateIrmaSchemas = true
	config.IrmaConfigPath = path.Join(testDirectory, "auth", "irma")
	config.ActingPartyCn = "CN=Awesomesoft"
	config.PublicUrl = "http://" + config.Address
	if err := os.MkdirAll(config.IrmaConfigPath, 0777); err != nil {
		logrus.Fatal(err)
	}
	if err := test2.CopyDir("../testdata/irma", config.IrmaConfigPath); err != nil {
		logrus.Fatal(err)
	}
	config.IrmaSchemeManager = "irma-demo"
	newInstance := pkg.NewAuthInstance(config, crypto.NewTestCryptoInstance(testDirectory), registry.NewTestRegistryInstance(testDirectory))
	if err := newInstance.Configure(); err != nil {
		logrus.Fatal(err)
	}

	return newInstance
}
