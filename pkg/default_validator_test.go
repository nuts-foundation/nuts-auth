package pkg

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-registry/pkg/events"

	"github.com/google/uuid"

	"github.com/lestrrat-go/jwx/jwk"

	"github.com/dgrijalva/jwt-go"

	"github.com/golang/mock/gomock"
	cryptoMock "github.com/nuts-foundation/nuts-crypto/mock"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-auth/testdata"
	irma2 "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

func TestDefaultValidator_IsInitialized(t *testing.T) {
	t.Run("No irma config returns false", func(t *testing.T) {
		v := DefaultValidator{}
		assert.False(t, v.IsInitialized())
	})

	t.Run("with irma config returns true", func(t *testing.T) {
		v := DefaultValidator{IrmaConfig: &irma2.Configuration{}}
		assert.True(t, v.IsInitialized())
	})
}

func TestValidateContract(t *testing.T) {
	type args struct {
		contract      string
		format        ContractFormat
		actingPartyCN string
		legalEntity   string
	}
	location, _ := time.LoadLocation("Europe/Amsterdam")
	tests := []struct {
		name    string
		args    args
		date    time.Time
		want    *ContractValidationResult
		wantErr bool
	}{
		{
			"a valid contract should be valid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				IrmaFormat,
				"Demo EHR",
				"verpleeghuis De nootjes",
			},
			// contract is valid at 1 oct 2019 11:46:00
			time.Date(2019, time.October, 1, 13, 46, 00, 0, location),
			&ContractValidationResult{
				Valid,
				IrmaFormat,
				map[string]string{"nuts.agb.agbcode": "00000007"},
			},
			false,
		},
		{
			"a valid contract with the wrong actingPartyCn is invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				IrmaFormat,
				"Awesome ECD!!",
				"legalEntity",
			},
			time.Date(2019, time.October, 1, 13, 46, 00, 0, location),
			&ContractValidationResult{
				Invalid,
				IrmaFormat,
				map[string]string{"nuts.agb.agbcode": "00000007"},
			},
			false,
		},
		{
			"a valid contract without a provided actingParty returns an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				IrmaFormat,
				"",
				"legalEntity",
			},
			time.Date(2019, time.October, 1, 13, 46, 00, 0, location),
			nil,
			true,
		},
		{
			"an expired contract should be invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				IrmaFormat,
				"Helder",
				"legalEntity",
			},
			time.Date(2019, time.October, 2, 13, 46, 00, 0, location),
			&ContractValidationResult{
				Invalid,
				IrmaFormat,
				map[string]string{"nuts.agb.agbcode": "00000007"},
			},
			false,
		},
		{
			"a forged contract it should be invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ForgedIrmaContract)),
				IrmaFormat,
				"Helder",
				"legalEntity",
			},
			time.Date(2019, time.October, 1, 13, 46, 00, 0, location),
			&ContractValidationResult{
				Invalid,
				IrmaFormat,
				nil,
			},
			false,
		},
		{
			"a valid but unknown contract should give an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidUnknownIrmaContract)),
				IrmaFormat,
				"Helder",
				"legalEntity",
			},
			time.Date(2019, time.May, 1, 16, 50, 00, 0, location),
			nil,
			true,
		},
		{
			"a valid json string which is not a contract should give an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.InvalidContract)),
				IrmaFormat,
				"Helder",
				"legalEntity",
			},
			time.Now(), // the contract does not have a valid date
			nil,
			true,
		},
		{
			"a random string should give an error",
			args{
				base64.StdEncoding.EncodeToString([]byte("some string which is not json")),
				IrmaFormat,
				"Helder",
				"legalEntity",
			},
			time.Now(), // the contract does not have a valid date
			nil,
			true,
		},
		{
			"an invalid base64 contract should give an error",
			args{
				"invalid base64",
				IrmaFormat,
				"Helder",
				"legalEntity",
			},
			time.Now(), // the contract does not have a valid date
			nil,
			true,
		},
		{
			"an unsupported format should give an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				"UnsupportedFormat",
				"Helder",
				"legalEntity",
			},
			time.Now(), // the contract does not have a valid date
			nil,
			true,
		},
	}

	authConfig := AuthConfig{
		IrmaConfigPath:            "../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	validator := DefaultValidator{IrmaServer: GetIrmaServer(authConfig), IrmaConfig: GetIrmaConfig(authConfig)}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//patch := monkey.Patch(time.Now, func() time.Time { return tt.date })
			NowFunc = func() time.Time { return tt.date }
			//defer patch.Unpatch()
			got, err := validator.ValidateContract(tt.args.contract, tt.args.format, tt.args.actingPartyCN)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateContract() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultValidator_SessionStatus(t *testing.T) {
	authConfig := AuthConfig{
		IrmaConfigPath:            "../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	signatureRequest := &irma2.SignatureRequest{
		Message: "Ik ga akkoord",
		DisclosureRequest: irma2.DisclosureRequest{
			BaseRequest: irma2.BaseRequest{
				Type: irma2.ActionSigning,
			},
			Disclose: irma2.AttributeConDisCon{
				irma2.AttributeDisCon{
					irma2.AttributeCon{
						irma2.NewAttributeRequest("irma-demo.nuts.agb.agbcode"),
					},
				},
			},
		},
	}

	_, knownSessionID, _ := GetIrmaServer(authConfig).StartSession(signatureRequest, func(result *server.SessionResult) {
		logrus.Infof("session done, result: %s", server.ToJson(result))
	})

	type fields struct {
		IrmaServer *irmaserver.Server
	}
	type args struct {
		id SessionID
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *SessionStatusResult
	}{
		{
			"for an unknown session, it returns nil",
			fields{GetIrmaServer(authConfig)},
			args{"unknown sessionId"},
			nil,
		},
		{
			"for a known session it returns a status",
			fields{GetIrmaServer(authConfig)},
			args{SessionID(knownSessionID)},
			&SessionStatusResult{
				server.SessionResult{Token: knownSessionID, Status: server.StatusInitialized, Type: irma2.ActionSigning},
				"",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := DefaultValidator{
				IrmaServer: tt.fields.IrmaServer,
			}

			got, _ := v.SessionStatus(tt.args.id)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultValidator.SessionStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockIrmaClient struct {
	err           error
	sessionResult server.SessionResult
}

func (m *mockIrmaClient) GetSessionResult(token string) *server.SessionResult {
	if m.err != nil {
		return nil
	}
	return &m.sessionResult
}

func (m *mockIrmaClient) StartSession(request interface{}, handler irmaserver.SessionHandler) (*irma2.Qr, string, error) {
	if m.err != nil {
		return nil, "", m.err
	}

	return nil, "", nil
}

// tests using mocks
func TestDefaultValidator_SessionStatus2(t *testing.T) {
	authConfig := AuthConfig{
		IrmaConfigPath:            "../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	t.Run("correct contract with registry lookup", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		rMock := registryMock.NewMockRegistryClient(ctrl)
		cMock := cryptoMock.NewMockClient(ctrl)
		iMock := mockIrmaClient{
			sessionResult: server.SessionResult{
				Token: "token",
				Signature: &irma2.SignedMessage{
					Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens verpleeghuis De nootjes en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
				},
			},
		}

		v := DefaultValidator{
			IrmaServer: &iMock,
			IrmaConfig: GetIrmaConfig(authConfig),
			Crypto:     cMock,
			Registry:   rMock,
		}

		rMock.EXPECT().ReverseLookup("verpleeghuis De nootjes").Return(&db.Organization{Identifier: "urn:id:1"}, nil)
		cMock.EXPECT().SignJwtFor(gomock.Any(), types.LegalEntity{URI: "urn:id:1"}).Return("token", nil)

		s, err := v.SessionStatus(SessionID("known"))

		assert.Nil(t, err)
		assert.NotNil(t, s)
		assert.Equal(t, "token", s.NutsAuthToken)
	})
}

func TestDefaultValidator_ValidateJwt(t *testing.T) {

	validator := defaultValidator()

	t.Run("valid jwt", func(t *testing.T) {

		oldFunc := NowFunc

		NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			NowFunc = oldFunc
		}()

		token := createJwt(OrganizationId, OrganizationId, testdata.ValidIrmaContract)
		actingParty := "Demo EHR"

		result, err := validator.ValidateJwt(string(token), actingParty)
		if assert.NoError(t, err) && assert.NotNil(t, result) {
			assert.Equal(t, ValidationState("VALID"), result.ValidationResult)
			assert.Equal(t, ContractFormat("irma"), result.ContractFormat)
			assert.Equal(t, map[string]string{"nuts.agb.agbcode": "00000007"}, result.DisclosedAttributes)
		}
	})

	t.Run("missing legalEntity", func(t *testing.T) {

		oldFunc := NowFunc

		NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			NowFunc = oldFunc
		}()

		var payload NutsIdentityToken

		var claims map[string]interface{}
		jsonString, _ := json.Marshal(payload)
		_ = json.Unmarshal(jsonString, &claims)

		token, err := cryptoInstance.SignJwtFor(claims, types.LegalEntity{URI: OrganizationId})
		if err != nil {
			t.FailNow()
		}

		actingParty := "Demo EHR"

		result, err := validator.ValidateJwt(token, actingParty)
		if assert.Nil(t, result) && assert.NotNil(t, err) {
			//assert.EqualError(t, err, ErrLegalEntityNotFound.Error())
			assert.True(t, strings.Contains(err.Error(), ErrLegalEntityNotFound.Error())) // jwt-go does not use Go 1.13 errors yet
		}
	})

	t.Run("invalid formatted jwt", func(t *testing.T) {
		token := "foo.bar.sig"

		result, err := validator.ValidateJwt(token, "actingParty")

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.EqualError(t, err, "invalid character '~' looking for beginning of value")
	})

	t.Run("invalid signature", func(t *testing.T) {
		oldFunc := NowFunc

		NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			NowFunc = oldFunc
		}()

		token := createJwt(OrganizationId, OrganizationId, testdata.ForgedIrmaContract)

		result, err := validator.ValidateJwt(string(token), "Demo EHR")

		if assert.NotNil(t, result) && assert.Nil(t, err) {
			assert.Equal(t, Invalid, result.ValidationResult)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		token := createJwt("wrong_issuer", OrganizationId, testdata.ValidIrmaContract)

		result, err := validator.ValidateJwt(string(token), "Demo EHR")
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Equal(t, "wrong_issuer: organization not found", err.Error())
	})

	t.Run("wrong scheme manager", func(t *testing.T) {
		oldFunc := NowFunc

		NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			NowFunc = oldFunc
		}()

		os.Setenv("NUTS_STRICTMODE", "true")
		cfg := core.NutsConfig()
		if err := cfg.Load(&cobra.Command{}); err != nil {
			t.Fatal("not expected error", err)
		}

		if assert.True(t, core.NutsConfig().InStrictMode()) {
			token := createJwt(OrganizationId, OrganizationId, testdata.ValidIrmaContract)
			actingParty := "Demo EHR"
			result, err := validator.ValidateJwt(string(token), actingParty)
			if assert.NoError(t, err) && assert.NotNil(t, result) {
				assert.Equal(t, ValidationState("INVALID"), result.ValidationResult)
			}
		}
		os.Unsetenv("NUTS_STRICTMODE")

	})

}

func TestDefaultValidator_createJwt(t *testing.T) {
	t.Run("Create valid JWT", func(t *testing.T) {
		oldFunc := NowFunc

		NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			NowFunc = oldFunc
		}()

		validator := defaultValidator()

		var c = SignedIrmaContract{}
		_ = json.Unmarshal([]byte(testdata.ValidIrmaContract), &c.IrmaContract)

		tokenString, err := validator.CreateIdentityTokenFromIrmaContract(&c, OrganizationId)

		if assert.Nil(t, err) && assert.NotEmpty(t, tokenString) {
			result, err := validator.ValidateJwt(tokenString, "Demo EHR")
			if assert.NoError(t, err) && assert.NotNil(t, result) {
				assert.Equal(t, Valid, result.ValidationResult)
			}
		}
	})
}

func TestDefaultValidator_legalEntityFromContract(t *testing.T) {
	type TestContext struct {
		ctrl  *gomock.Controller
		v     DefaultValidator
		rMock *registryMock.MockRegistryClient
	}
	createContext := func(t *testing.T) TestContext {
		ctrl := gomock.NewController(t)
		rMock := registryMock.NewMockRegistryClient(ctrl)

		v := DefaultValidator{
			Registry: rMock,
		}

		return TestContext{ctrl: ctrl, v: v, rMock: rMock}
	}

	t.Run("Empty message returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		_, err := ctx.v.legalEntityFromContract(SignedIrmaContract{IrmaContract: irma2.SignedMessage{}})

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrInvalidContractText))
	})

	t.Run("Missing legalEntity returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		_, err := ctx.v.legalEntityFromContract(SignedIrmaContract{
			IrmaContract: irma2.SignedMessage{
				Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens  en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
			},
		})

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrInvalidContractText))
	})

	t.Run("Unknown legalEntity returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.rMock.EXPECT().ReverseLookup("UNKNOWN").Return(nil, db.ErrOrganizationNotFound)

		_, err := ctx.v.legalEntityFromContract(SignedIrmaContract{
			IrmaContract: irma2.SignedMessage{
				Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens UNKNOWN en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
			},
		})

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, db.ErrOrganizationNotFound))
	})
}

func TestDefaultValidator_ParseAndValidateJwtBearerToken(t *testing.T) {
	t.Run("malformed access tokens", func(t *testing.T) {
		validator := defaultValidator()

		response, err := validator.ParseAndValidateJwtBearerToken("foo")
		assert.Nil(t, response)
		assert.Equal(t, "token contains an invalid number of segments", err.Error())

		response, err = validator.ParseAndValidateJwtBearerToken("123.456.787")
		assert.Nil(t, response)
		assert.Equal(t, "invalid character '×' looking for beginning of value", err.Error())
	})

	t.Run("wrong signing algorithm", func(t *testing.T) {
		validator := defaultValidator()
		// alg: HS256
		const invalidJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MDAwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjo0MDcwOTA4ODAwLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.2_4bxKKsVspQ4QxXRG8m2mOnLbl-fFgSkEq_h8N9sNE"
		response, err := validator.ParseAndValidateJwtBearerToken(invalidJwt)
		assert.Nil(t, response)
		assert.Equal(t, "signing method HS256 is invalid", err.Error())
	})

	t.Run("missing issuer", func(t *testing.T) {
		validator := defaultValidator()
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
		validJwt, err := validator.Crypto.SignJwtFor(claims, types.LegalEntity{URI: OrganizationId})
		assert.Nil(t, err)
		response, err := validator.ParseAndValidateJwtBearerToken(validJwt)
		assert.Nil(t, response)
		assert.Equal(t, "legalEntity not provided", err.Error())
	})

	t.Run("unknown issuer", func(t *testing.T) {
		validator := defaultValidator()
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
		validJwt, err := validator.Crypto.SignJwtFor(claims, types.LegalEntity{URI: OrganizationId})
		assert.Nil(t, err)
		response, err := validator.ParseAndValidateJwtBearerToken(validJwt)
		assert.Nil(t, response)
		assert.Equal(t, "urn:oid:2.16.840.1.113883.2.4.6.1:10000001: organization not found", err.Error())
	})

	t.Run("token not signed by issuer", func(t *testing.T) {
		validator := defaultValidator()

		claims := map[string]interface{}{
			"iss": OtherOrganizationId,
			"sub": "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
			"sid": "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			"aud": "https://target_token_endpoint",
			"usi": "base64 encoded signature",
			"exp": 4070908800,
			"iat": 1578910481,
			"jti": "123-456-789",
		}

		otherParty := types.LegalEntity{URI: OrganizationId}

		validJwt, err := validator.Crypto.SignJwtFor(claims, otherParty)
		if !assert.Nil(t, err) {
			t.FailNow()
		}
		response, err := validator.ParseAndValidateJwtBearerToken(validJwt)
		assert.Nil(t, response)
		assert.Equal(t, "crypto/rsa: verification error", err.Error())
	})

	t.Run("token expired", func(t *testing.T) {
		validator := defaultValidator()

		claims := map[string]interface{}{
			"iss": OrganizationId,
			"sub": "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
			"sid": "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			"aud": "https://target_token_endpoint",
			"usi": "base64 encoded signature",
			"exp": 1578910481,
			"iat": 1578910481,
			"jti": "123-456-789",
		}

		validJwt, err := validator.Crypto.SignJwtFor(claims, types.LegalEntity{URI: claims["iss"].(string)})
		assert.Nil(t, err)
		response, err := validator.ParseAndValidateJwtBearerToken(validJwt)
		assert.Nil(t, response)
		assert.Contains(t, err.Error(), "token is expired by")
	})

	t.Run("valid jwt", func(t *testing.T) {
		validator := defaultValidator()

		//claims := map[string]interface{}{
		//	"iss": OrganizationId,
		//	"sub": "urn:oid:2.16.840.1.113883.2.4.6.1:12481248",
		//	"sid": "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
		//	"aud": "https://target_token_endpoint",
		//	"usi": "base64 encoded signature",
		//	"exp": 4070908800,
		//	"iat": 1578910481,
		//	"jti": "123-456-789",
		//}
		claims := NutsJwtBearerToken{
			StandardClaims: jwt.StandardClaims{
				Audience:  "https://target_token_endpoint",
				ExpiresAt: 4070908800,
				Id:        "123-456-789",
				IssuedAt:  1578910481,
				Issuer:    OrganizationId,
			},
			Custodian:     OtherOrganizationId,
			IdentityToken: "base64 encoded signature",
			SubjectId:     "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			Scope:         "nuts-sso",
		}

		var inInterface map[string]interface{}
		inrec, _ := json.Marshal(claims)
		_ = json.Unmarshal(inrec, &inInterface)

		//_ = validator.crypto.GenerateKeyPairFor(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:12481248"})
		validAccessToken, err := validator.Crypto.SignJwtFor(inInterface, types.LegalEntity{URI: claims.Issuer})
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		response, err := validator.ParseAndValidateJwtBearerToken(validAccessToken)
		assert.NoError(t, err)
		assert.NotEmpty(t, response)
	})
}

func createJwt(iss string, sub string, contractStr string) []byte {
	contract := SignedIrmaContract{}
	err := json.Unmarshal([]byte(contractStr), &contract.IrmaContract)
	if err != nil {
		panic(err)
	}

	encodedContract := base64.StdEncoding.EncodeToString([]byte(contractStr))

	var payload NutsIdentityToken
	payload.Issuer = iss
	payload.Type = IrmaFormat
	payload.Subject = sub
	payload.Signature = encodedContract

	jsonString, _ := json.Marshal(payload)
	var claims map[string]interface{}
	_ = json.Unmarshal(jsonString, &claims)

	tokenString, _ := cryptoInstance.SignJwtFor(claims, types.LegalEntity{URI: sub})

	return []byte(tokenString)
}

var cryptoInstance = &crypto.Crypto{
	Config: crypto.CryptoConfig{
		Keysize: types.ConfigKeySizeDefault,
		Fspath:  "../testdata/tmp",
	},
}
var testInstance *DefaultValidator

const OrganizationId = "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"
const OtherOrganizationId = "urn:oid:2.16.840.1.113883.2.4.6.1:00000002"

// defaultValidator sets up a validator with a registry containing a single test organization.
// The method is a singleton and always returns the same instance
func defaultValidator() DefaultValidator {
	mutex := sync.Mutex{}
	mutex.Lock()
	defer mutex.Unlock()

	if testInstance == nil {

		r := registry.RegistryInstance()
		r.Config.Mode = "server"
		r.Config.Datadir = "../testdata/registry"
		r.Config.SyncMode = "fs"
		if err := r.Configure(); err != nil {
			panic(err)
		}

		if err := cryptoInstance.Configure(); err != nil {
			panic(err)
		}

		// Register a vendor
		event, _ := events.CreateEvent(events.RegisterVendor, events.RegisterVendorEvent{Identifier: "oid:123", Name: "Awesomesoft"})
		if err := r.EventSystem.PublishEvent(event); err != nil {
			panic(err)
		}

		// Generate keys for Organization
		le := types.LegalEntity{URI: OrganizationId}
		_ = cryptoInstance.GenerateKeyPairFor(le)
		pub, _ := cryptoInstance.PublicKeyInJWK(le)

		// Add Organization to registry
		event, _ = events.CreateEvent(events.VendorClaim, events.VendorClaimEvent{
			VendorIdentifier: "oid:123",
			OrgIdentifier:    OrganizationId,
			OrgName:          "Zorggroep Nuts",
			OrgKeys:          []interface{}{pub},
		})
		if err := r.EventSystem.PublishEvent(event); err != nil {
			panic(err)
		}

		// Generate public key by hand so the private key does not end up on disk
		reader := rand.Reader
		key, err := rsa.GenerateKey(reader, 2048)
		if err != nil {
			panic(err)
		}
		pub, err = jwk.New(&key.PublicKey)
		if err != nil {
			panic(err)
		}

		// add OtherOrganization to registry
		event, _ = events.CreateEvent(events.VendorClaim, events.VendorClaimEvent{
			VendorIdentifier: "oid:123",
			OrgIdentifier:    OtherOrganizationId,
			OrgName:          "verpleeghuis De nootjes",
			OrgKeys:          []interface{}{pub},
		})
		if err := r.EventSystem.PublishEvent(event); err != nil {
			panic(err)
		}

		// Add oauth endpoint to OtherOrganization
		event, _ = events.CreateEvent(events.RegisterEndpoint, events.RegisterEndpointEvent{
			Organization: OtherOrganizationId,
			URL:          "tcp://127.0.0.1:1234",
			EndpointType: SsoEndpointType,
			Identifier:   "1f7d4ea7-c1cf-4c14-ba23-7e1fddc31ad1",
			Status:       "active",
			Version:      "0.1",
		})
		if err := r.EventSystem.PublishEvent(event); err != nil {
			panic(err)
			//=======
			//		_ = cryptoInstance.GenerateKeyPairFor(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"})
			//		{
			//			vendorEvent, err := events.CreateEvent(events.RegisterVendor, events.RegisterVendorEvent{
			//				Identifier: "1",
			//				Name:       "BecauseWeCare Software",
			//			})
			//			if err != nil {
			//				panic(err)
			//			}
			//			if err := r.EventSystem.PublishEvent(vendorEvent); err != nil {
			//				panic(err)
			//			}
			//		}
			//		{
			//			le := types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"}
			//			_ = cryptoInstance.GenerateKeyPairFor(le)
			//			pub, _ := cryptoInstance.PublicKeyInJWK(le)
			//			pubJwkAsMap, _ := crypto.JwkToMap(pub)
			//			claimEvent, err := events.CreateEvent(events.VendorClaim, events.VendorClaimEvent{
			//				VendorIdentifier: "1",
			//				OrgIdentifier:    "urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
			//				OrgName:          "verpleeghuis De nootjes",
			//				OrgKeys:          []interface{}{pubJwkAsMap},
			//			})
			//			if err != nil {
			//				panic(err)
			//			}
			//			if err := r.EventSystem.PublishEvent(claimEvent); err != nil {
			//				panic(err)
			//			}
			//>>>>>>> master
		}

		testInstance = &DefaultValidator{
			Registry: r,
			Crypto:   cryptoInstance,
			IrmaConfig: GetIrmaConfig(AuthConfig{
				IrmaConfigPath:            "../testdata/irma",
				SkipAutoUpdateIrmaSchemas: true,
			}),
		}
	}

	return *testInstance
}

func TestDefaultValidator_BuildAccessToken(t *testing.T) {
	t.Run("missing subject", func(t *testing.T) {
		v := defaultValidator()
		claims := &NutsJwtBearerToken{}
		identityValidationResult := &ContractValidationResult{ValidationResult: Valid}
		token, err := v.BuildAccessToken(claims, identityValidationResult)
		assert.Empty(t, token)
		assert.EqualError(t, err, "could not build accessToken: subject is missing")
	})

	t.Run("build an access token", func(t *testing.T) {
		v := defaultValidator()
		claims := &NutsJwtBearerToken{StandardClaims: jwt.StandardClaims{Subject: OrganizationId}}
		identityValidationResult := &ContractValidationResult{ValidationResult: Valid}
		token, err := v.BuildAccessToken(claims, identityValidationResult)
		if assert.NotEmpty(t, token) {
			token, err := jwt.Parse(token, func(token *jwt.Token) (i interface{}, err error) {
				org, _ := v.Registry.OrganizationById(claims.Subject)
				pk, _ := org.CurrentPublicKey()
				return pk.Materialize()
			})
			if assert.Nil(t, err) {
				if assert.True(t, token.Valid) {
					if tokenClaims, ok := token.Claims.(jwt.MapClaims); ok {
						assert.Equal(t, claims.Subject, tokenClaims["iss"])
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
		v := defaultValidator()
		request := CreateJwtBearerTokenRequest{
			Custodian:     OtherOrganizationId,
			Actor:         OrganizationId,
			Subject:       "789",
			IdentityToken: "irma identity token",
			Scope:         "nuts-sso",
		}
		token, err := v.CreateJwtBearerToken(&request)

		if !assert.Nil(t, err) {
			t.FailNow()
		}
		assert.NotEmpty(t, token.BearerToken)
		parts := strings.Split(token.BearerToken, ".")
		bytes, _ := jwt.DecodeSegment(parts[1])
		var claims map[string]interface{}
		if !assert.Nil(t, json.Unmarshal(bytes, &claims)) {
			t.FailNow()
		}

		assert.Equal(t, OrganizationId, claims["iss"])
		assert.Equal(t, OtherOrganizationId, claims["sub"])
		assert.Equal(t, request.Subject, claims["sid"])
		assert.Equal(t, "1f7d4ea7-c1cf-4c14-ba23-7e1fddc31ad1", claims["aud"])
		assert.Equal(t, request.IdentityToken, claims["usi"])
		//assert.Equal(t, request.Scope.([]interface{}), claims["scope"])
	})

	t.Run("invalid custodian", func(t *testing.T) {
		v := defaultValidator()

		request := CreateJwtBearerTokenRequest{
			Custodian:     "123",
			Actor:         OrganizationId,
			Subject:       "789",
			IdentityToken: "irma identity token",
		}

		token, err := v.CreateJwtBearerToken(&request)

		assert.Empty(t, token)
		if !assert.NotNil(t, err) {
			t.Fail()
		}
		assert.Contains(t, err.Error(), "token endpoint not found")
	})

	t.Run("invalid actor", func(t *testing.T) {
		v := defaultValidator()

		request := CreateJwtBearerTokenRequest{
			Custodian:     OtherOrganizationId,
			Actor:         "456",
			Subject:       "789",
			IdentityToken: "irma identity token",
		}

		token, err := v.CreateJwtBearerToken(&request)

		assert.Empty(t, token)
		if !assert.NotNil(t, err) {
			t.Fail()
		}
		assert.Contains(t, err.Error(), "could not open entry for legalEntity")
	})
	t.Run("custodian without endpoint", func(t *testing.T) {
		v := defaultValidator()

		request := CreateJwtBearerTokenRequest{
			Custodian:     OrganizationId,
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
	tokenId, _ := uuid.NewRandom()
	buildClaims := NutsJwtBearerToken{
		StandardClaims: jwt.StandardClaims{
			Audience:  "",
			Id:        tokenId.String(),
			IssuedAt:  time.Now().Unix(),
			Issuer:    OtherOrganizationId,
			NotBefore: time.Now().Unix(),
			ExpiresAt: time.Now().Add(10 * time.Minute).Unix(),
			Subject:   OrganizationId,
		},
		SubjectId:     "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
		IdentityToken: "base64 encoded identity ",
		Scope:         "nuts-sso",
	}

	userIdentityValidationResult := ContractValidationResult{
		ValidationResult:    Valid,
		ContractFormat:      "",
		DisclosedAttributes: map[string]string{"nuts.agb.agbcode": "1234"},
	}

	t.Run("token not issued by care provider of this node", func(t *testing.T) {

		v := defaultValidator()

		// Use this code to regenerate the token if needed. Don't forget to delete the private keys from the testdata afterwards
		//localBuildClaims := buildClaims
		//localBuildClaims.Subject = "unknown-party"
		//v.crypto.GenerateKeyPairFor(types.LegalEntity{URI: localBuildClaims.Subject})
		//token, err := v.BuildAccessToken(&localBuildClaims, &userIdentityValidationResult)
		//t.Log(token)

		token := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhaWQiOiIiLCJleHAiOjE1ODE1OTk5ODQsImlhdCI6MTU4MTU5OTA4NCwiaXNzIjoidW5rbm93bi1wYXJ0eSIsInNpZCI6IiIsInN1YiI6IjEyMzQifQ.Ot9Az8tv28w2TrwuRMHAUGMdzYTw5JlwphTT1eFaxCC-8j00Pps_UHAQfQIe-5sAePgqmMrh8D_P-xxUmFNyTD6azYcw45G0nQyFcc1hvo5Hc5Ib2SMIA_W1UHIZnEUoERpoK3cZPvHKaRx4SKIqZtG1ylJPEDv3dV2MBrBroQYXBWzKOzzE6O3SjP3al9L8QzD4rZ21QtRMDKdmTfuGKqMT1u3odf49jMEdzvVpSsDeXzGonHm0SXi6TTt0Dc5ewdIRus14m3wNEsx4auPYDl012q7N02w5zMRVdVWlhkoatm5i1GIBkagKQ26ICNyK0jL6djkcPC-ZgKvSVmiv-Q"

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
		v := defaultValidator()
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
		assert.Equal(t, OrganizationId, claims.Issuer)
		// Check the other organization is the subject
		assert.Equal(t, OtherOrganizationId, claims.Subject)
		// Check the if SubjectId contains the citizen service number
		assert.Equal(t, buildClaims.SubjectId, claims.SubjectId)
		assert.Equal(t, "nuts-sso", claims.Scope)
	})
}
