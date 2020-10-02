package oauth

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	"github.com/nuts-foundation/nuts-go-test/io"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	registryTest "github.com/nuts-foundation/nuts-registry/test"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-auth/pkg/services"
	"github.com/nuts-foundation/nuts-auth/test"
)

func TestDefaultValidator_ParseAndValidateJwtBearerToken(t *testing.T) {
	t.Run("malformed access tokens", func(t *testing.T) {
		validator := defaultValidator(t)

		response, err := validator.ParseAndValidateJwtBearerToken("foo")
		assert.Nil(t, response)
		assert.Equal(t, "token contains an invalid number of segments", err.Error())

		response, err = validator.ParseAndValidateJwtBearerToken("123.456.787")
		assert.Nil(t, response)
		assert.Equal(t, "invalid character '×' looking for beginning of value", err.Error())
	})

	t.Run("wrong signing algorithm", func(t *testing.T) {
		validator := defaultValidator(t)
		// alg: HS256
		const invalidJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MDAwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjo0MDcwOTA4ODAwLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.2_4bxKKsVspQ4QxXRG8m2mOnLbl-fFgSkEq_h8N9sNE"
		response, err := validator.ParseAndValidateJwtBearerToken(invalidJwt)
		assert.Nil(t, response)
		assert.Equal(t, "signing method HS256 is invalid", err.Error())
	})

	t.Run("missing issuer", func(t *testing.T) {
		validator := defaultValidator(t)
		claims := map[string]interface{}{
			"iss": "",
			"sub": "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
			"sid": "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			"aud": "https://target_token_endpoint",
			"usi": "base64 encoded signature",
			"exp": 4070908800,
			"iat": 1578910481,
			"jti": "123-456-789",
		}
		validJwt, err := validator.Crypto.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: organizationID.String()}))
		assert.Nil(t, err)
		response, err := validator.ParseAndValidateJwtBearerToken(validJwt)
		assert.Nil(t, response)
		assert.Equal(t, "legalEntity not provided", err.Error())
	})

	t.Run("unknown issuer", func(t *testing.T) {
		validator := defaultValidator(t)
		claims := map[string]interface{}{
			"iss": "urn:oid:2.16.840.1.113883.2.4.6.1:10000001",
			"sub": "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
			"sid": "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			"aud": "https://target_token_endpoint",
			"usi": "base64 encoded signature",
			"exp": 4070908800,
			"iat": 1578910481,
			"jti": "123-456-789",
		}
		validJwt, err := validator.Crypto.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: organizationID.String()}))
		assert.Nil(t, err)
		response, err := validator.ParseAndValidateJwtBearerToken(validJwt)
		assert.Nil(t, response)
		assert.Equal(t, "urn:oid:2.16.840.1.113883.2.4.6.1:10000001: organization not found", err.Error())
	})

	t.Run("token not signed by issuer", func(t *testing.T) {
		validator := defaultValidator(t)

		claims := map[string]interface{}{
			"iss": otherOrganizationID,
			"sub": "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
			"sid": "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			"aud": "https://target_token_endpoint",
			"usi": "base64 encoded signature",
			"exp": 4070908800,
			"iat": 1578910481,
			"jti": "123-456-789",
		}

		validJwt, err := validator.Crypto.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: organizationID.String()}))
		if !assert.Nil(t, err) {
			t.FailNow()
		}
		response, err := validator.ParseAndValidateJwtBearerToken(validJwt)
		assert.Nil(t, response)
		assert.Equal(t, "crypto/rsa: verification error", err.Error())
	})

	t.Run("token expired", func(t *testing.T) {
		validator := defaultValidator(t)

		claims := map[string]interface{}{
			"iss": organizationID,
			"sub": "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
			"sid": "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			"aud": "https://target_token_endpoint",
			"usi": "base64 encoded signature",
			"exp": 1578910481,
			"iat": 1578910481,
			"jti": "123-456-789",
		}

		validJwt, err := validator.Crypto.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: claims["iss"].(core.PartyID).String()}))
		assert.Nil(t, err)
		response, err := validator.ParseAndValidateJwtBearerToken(validJwt)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "token is expired by")
	})

	t.Run("valid jwt", func(t *testing.T) {
		validator := defaultValidator(t)

		//claims := map[string]interface{}{
		//	"iss": organizationID,
		//	"sub": "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
		//	"sid": "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
		//	"aud": "https://target_token_endpoint",
		//	"usi": "base64 encoded signature",
		//	"exp": 4070908800,
		//	"iat": 1578910481,
		//	"jti": "123-456-789",
		//}
		claims := services.NutsJwtBearerToken{
			StandardClaims: jwt.StandardClaims{
				Audience:  "https://target_token_endpoint",
				ExpiresAt: 4070908800,
				Id:        "123-456-789",
				IssuedAt:  1578910481,
				Issuer:    organizationID.String(),
				Subject:   otherOrganizationID.String(),
			},
			AuthTokenContainer: "base64 encoded signature",
			SubjectID:          "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			Scope:              "nuts-sso",
		}

		var inInterface map[string]interface{}
		inrec, _ := json.Marshal(claims)
		_ = json.Unmarshal(inrec, &inInterface)

		//_ = validator.crypto.GenerateKeyPairFor(cryptoTypes.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:12481248"})
		validAccessToken, err := validator.Crypto.SignJWT(inInterface, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: claims.Issuer}))
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		response, err := validator.ParseAndValidateJwtBearerToken(validAccessToken)
		assert.NoError(t, err)
		assert.NotEmpty(t, response)
	})
}

func TestDefaultValidator_BuildAccessToken(t *testing.T) {
	t.Run("missing subject", func(t *testing.T) {
		v := defaultValidator(t)
		claims := &services.NutsJwtBearerToken{}
		identityValidationResult := &services.ContractValidationResult{ValidationResult: services.Valid}
		token, err := v.BuildAccessToken(claims, identityValidationResult)
		assert.Empty(t, token)
		assert.EqualError(t, err, "could not build accessToken: subject is missing")
	})

	t.Run("build an access token", func(t *testing.T) {
		v := defaultValidator(t)
		claims := &services.NutsJwtBearerToken{StandardClaims: jwt.StandardClaims{Subject: organizationID.String()}}
		identityValidationResult := &services.ContractValidationResult{ValidationResult: services.Valid}
		token, err := v.BuildAccessToken(claims, identityValidationResult)
		if assert.NotEmpty(t, token) {
			subject, _ := core.ParsePartyID(claims.Subject)
			token, err := jwt.Parse(token, func(token *jwt.Token) (i interface{}, err error) {
				org, _ := v.Registry.OrganizationById(subject)
				pk, _ := org.CurrentPublicKey()
				return pk.Materialize()
			})
			if assert.Nil(t, err) {
				if assert.True(t, token.Valid) {
					if tokenClaims, ok := token.Claims.(jwt.MapClaims); ok {
						assert.Equal(t, subject.String(), tokenClaims["iss"])
						assert.InDelta(t, tokenClaims["iat"].(float64), time.Now().Unix(), float64(time.Second*2))
						assert.InDelta(t, tokenClaims["exp"].(float64), time.Now().Add(15*time.Minute).Unix(), float64(time.Second*2))
					}
				}
			}
		}

		assert.Nil(t, err)
	})

}

func TestDefaultValidator_CreateJwtBearerToken(t *testing.T) {
	t.Run("create a JwtBearerToken", func(t *testing.T) {
		v := defaultValidator(t)
		request := services.CreateJwtBearerTokenRequest{
			Custodian:     otherOrganizationID.String(),
			Actor:         organizationID.String(),
			Subject:       "789",
			IdentityToken: "irma identity token",
			Scope:         "nuts-sso",
		}
		token, err := v.CreateJwtBearerToken(&request)

		if !assert.Nil(t, err) || !assert.NotEmpty(t, token.BearerToken) {
			t.FailNow()
		}
		parts := strings.Split(token.BearerToken, ".")
		bytes, _ := jwt.DecodeSegment(parts[1])
		var claims map[string]interface{}
		if !assert.Nil(t, json.Unmarshal(bytes, &claims)) {
			t.FailNow()
		}

		assert.Equal(t, organizationID.String(), claims["iss"])
		assert.Equal(t, otherOrganizationID.String(), claims["sub"])
		assert.Equal(t, request.Subject, claims["sid"])
		// audience check is disabled since the relationship between endpoints, scopes and bolts is not yet defined
		//assert.Equal(t, "1f7d4ea7-c1cf-4c14-ba23-7e1fddc31ad1", claims["aud"])
		assert.Equal(t, request.IdentityToken, claims["usi"])
		assert.Equal(t, request.Scope, claims["scope"])
	})

	t.Run("invalid custodian", func(t *testing.T) {
		t.Skip("Disabled for now since the relation between scope, custodians and endpoints is not yet clear.")
		v := defaultValidator(t)

		request := services.CreateJwtBearerTokenRequest{
			Custodian:     "123",
			Actor:         organizationID.String(),
			Subject:       "789",
			IdentityToken: "irma identity token",
		}

		token, err := v.CreateJwtBearerToken(&request)

		if !assert.Empty(t, token) || !assert.Error(t, err) {
			t.FailNow()
		}
		assert.Contains(t, err.Error(), "token endpoint not found")
	})

	t.Run("invalid actor", func(t *testing.T) {
		v := defaultValidator(t)

		request := services.CreateJwtBearerTokenRequest{
			Custodian:     otherOrganizationID.String(),
			Actor:         "456",
			Subject:       "789",
			IdentityToken: "irma identity token",
		}

		token, err := v.CreateJwtBearerToken(&request)

		assert.Empty(t, token)
		if !assert.NotNil(t, err) {
			t.Fail()
		}
		assert.Contains(t, err.Error(), "could not open entry")
	})
	t.Run("custodian without endpoint", func(t *testing.T) {
		t.Skip("Disabled for now since the relation between scope, custodians and endpoints is not yet clear.")
		v := defaultValidator(t)

		request := services.CreateJwtBearerTokenRequest{
			Custodian:     organizationID.String(),
			Actor:         "456",
			Subject:       "789",
			IdentityToken: "irma identity token",
		}

		token, err := v.CreateJwtBearerToken(&request)

		assert.Empty(t, token)
		if !assert.NotNil(t, err) {
			t.Fail()
		}
		assert.Contains(t, err.Error(), "none or multiple registred sso endpoints found")
	})
}

func TestDefaultValidator_ValidateAccessToken(t *testing.T) {
	tokenID, _ := uuid.NewRandom()
	buildClaims := services.NutsJwtBearerToken{
		StandardClaims: jwt.StandardClaims{
			Audience:  "",
			Id:        tokenID.String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    otherOrganizationID.String(),
			NotBefore: time.Now().Unix(),
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
			Subject:   organizationID.String(),
		},
		SubjectID:          "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
		AuthTokenContainer: "base64 encoded identity ",
		Scope:              "nuts-sso",
	}

	userIdentityValidationResult := services.ContractValidationResult{
		ValidationResult:    services.Valid,
		ContractFormat:      "",
		DisclosedAttributes: map[string]string{"nuts.agb.agbcode": "1234"},
	}

	t.Run("token not issued by care provider of this node", func(t *testing.T) {

		v := defaultValidator(t)

		// Use this code to regenerate the token if needed. Don't forget to delete the private keys from the testdata afterwards
		//localBuildClaims := buildClaims
		//localBuildClaims.Subject = registryTest.OrganizationID("unknown-party").String()
		//c.GenerateKeyPair(cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: localBuildClaims.Subject}))
		//token, err := v.BuildAccessToken(&localBuildClaims, &userIdentityValidationResult)
		//t.Log(token)

		token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJlbWFpbCI6IiIsImV4cCI6MTU5NjUzOTkwNSwiZmFtaWx5X25hbWUiOiIiLCJnaXZlbl9uYW1lIjoiIiwiaWF0IjoxNTk2NTM5MDA1LCJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6dW5rbm93bi1wYXJ0eSIsIm5hbWUiOiIiLCJwcmVmaXgiOiIiLCJzY29wZSI6Im51dHMtc3NvIiwic2lkIjoidXJuOm9pZDoyLjE2Ljg0MC4xLjExMzg4My4yLjQuNi4zOjk5OTk5OTAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MDAwMDAwMDIifQ.hCDVxoZ9mYdMRzHmgcFpPcQFKXf1LBorBH8lr2HZ1k04QVoSLfOjcImglwibXtBNEjbQ3zggmzNI9R1FvTLnmDCN6A-Z1DsJtBLVfZkQOS1kYFlYj7KFGVCQpyAJR4O-LPeYx1_TgkRsSaKQKaonQkA3Vaq9LD-hHh59xQ1sOVk"

		claims, err := v.ParseAndValidateAccessToken(token)
		if !assert.Error(t, err) || !assert.Nil(t, claims) {
			t.FailNow()
		}
		assert.Equal(t, "invalid token: not signed by a care provider of this node", err.Error())
	})

	// Other organization sends access token to Organization in a request.
	// Validate the Access Token
	// Everything should be fine
	t.Run("validate access token", func(t *testing.T) {
		v := defaultValidator(t)
		// First build an access token
		token, err := v.BuildAccessToken(&buildClaims, &userIdentityValidationResult)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		// Then validate it
		claims, err := v.ParseAndValidateAccessToken(token)
		if !assert.NoError(t, err) || !assert.NotNil(t, claims) {
			t.FailNow()
		}

		// Check this organization signed the access token
		assert.Equal(t, organizationID.String(), claims.Issuer)
		// Check the other organization is the subject
		assert.Equal(t, otherOrganizationID.String(), claims.Subject)
		// Check the if SubjectID contains the citizen service number
		assert.Equal(t, buildClaims.SubjectID, claims.SubjectID)
		assert.Equal(t, "nuts-sso", claims.Scope)
	})
}

var organizationID = registryTest.OrganizationID("00000001")
var otherOrganizationID = registryTest.OrganizationID("00000002")

// defaultValidator sets up a validator with a registry containing a single test organization.
// The method is a singleton and always returns the same instance
func defaultValidator(t *testing.T) OAuthService {
	t.Helper()
	os.Setenv("NUTS_IDENTITY", registryTest.VendorID("1234").String())
	core.NutsConfig().Load(&cobra.Command{})
	testDirectory := io.TestDirectory(t)
	testCrypto := crypto.NewTestCryptoInstance(testDirectory)
	testRegistry := registry.NewTestRegistryInstance(testDirectory)

	// Register a vendor
	test.RegisterVendor(t, "Awesomesoft", testCrypto, testRegistry)

	// Add Organization to registry
	if _, err := testRegistry.VendorClaim(organizationID, "Zorggroep Nuts", nil); err != nil {
		t.Fatal(err)
	}

	if _, err := testRegistry.VendorClaim(otherOrganizationID, "verpleeghuis De nootjes", nil); err != nil {
		t.Fatal(err)
	}
	return OAuthService{
		Registry: testRegistry,
		Crypto:   testCrypto,
	}
}
