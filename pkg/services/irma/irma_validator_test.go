package irma

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-auth/pkg/services"

	registry "github.com/nuts-foundation/nuts-registry/pkg"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"

	"github.com/nuts-foundation/nuts-auth/test"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-go-test/io"

	"github.com/google/uuid"
	registryTest "github.com/nuts-foundation/nuts-registry/test"

	"github.com/dgrijalva/jwt-go"

	"github.com/golang/mock/gomock"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	cryptoMock "github.com/nuts-foundation/nuts-crypto/test/mock"
	core "github.com/nuts-foundation/nuts-go-core"
	registryMock "github.com/nuts-foundation/nuts-registry/mock"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"

	"github.com/nuts-foundation/nuts-auth/testdata"
	irma "github.com/privacybydesign/irmago"
	irmaservercore "github.com/privacybydesign/irmago/server"
	irmaserver "github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

func TestDefaultValidator_IsInitialized(t *testing.T) {
	t.Run("No irma config returns false", func(t *testing.T) {
		v := IrmaMethod{}
		assert.False(t, v.IsInitialized())
	})

	t.Run("with irma config returns true", func(t *testing.T) {
		v := IrmaMethod{IrmaConfig: &irma.Configuration{}}
		assert.True(t, v.IsInitialized())
	})
}

func TestValidateContract(t *testing.T) {
	type args struct {
		contract      string
		format        services.ContractFormat
		actingPartyCN string
		legalEntity   string
	}
	location, _ := time.LoadLocation("Europe/Amsterdam")
	tests := []struct {
		name    string
		args    args
		date    time.Time
		want    *services.ContractValidationResult
		wantErr bool
	}{
		{
			"a valid contract should be valid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				services.IrmaFormat,
				"Demo EHR",
				"verpleeghuis De nootjes",
			},
			// contract is valid at 1 oct 2019 11:46:00
			time.Date(2019, time.October, 1, 13, 46, 00, 0, location),
			&services.ContractValidationResult{
				services.Valid,
				services.IrmaFormat,
				map[string]string{"nuts.agb.agbcode": "00000007"},
			},
			false,
		},
		{
			"a valid contract with the wrong actingPartyCn is invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				services.IrmaFormat,
				"Awesome ECD!!",
				"legalEntity",
			},
			time.Date(2019, time.October, 1, 13, 46, 00, 0, location),
			&services.ContractValidationResult{
				services.Invalid,
				services.IrmaFormat,
				map[string]string{"nuts.agb.agbcode": "00000007"},
			},
			false,
		},
		{
			"a valid contract without a provided actingParty returns an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				services.IrmaFormat,
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
				services.IrmaFormat,
				"Helder",
				"legalEntity",
			},
			time.Date(2019, time.October, 2, 13, 46, 00, 0, location),
			&services.ContractValidationResult{
				services.Invalid,
				services.IrmaFormat,
				map[string]string{"nuts.agb.agbcode": "00000007"},
			},
			false,
		},
		{
			"a forged contract it should be invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ForgedIrmaContract)),
				services.IrmaFormat,
				"Helder",
				"legalEntity",
			},
			time.Date(2019, time.October, 1, 13, 46, 00, 0, location),
			&services.ContractValidationResult{
				services.Invalid,
				services.IrmaFormat,
				nil,
			},
			false,
		},
		{
			"a valid but unknown contract should give an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidUnknownIrmaContract)),
				services.IrmaFormat,
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
				services.IrmaFormat,
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
				services.IrmaFormat,
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
				services.IrmaFormat,
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

	authConfig := IrmaServiceConfig{
		IrmaConfigPath:            "../../../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	irmaConfig, _ := GetIrmaConfig(authConfig)
	irmaServer, _ := GetIrmaServer(authConfig)
	validator := IrmaMethod{IrmaSessionHandler: irmaServer, IrmaConfig: irmaConfig, ValidContracts: contract.Contracts}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract.NowFunc = func() time.Time { return tt.date }
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
	serviceConfig := IrmaServiceConfig{
		IrmaConfigPath:            "../../../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	signatureRequest := &irma.SignatureRequest{
		Message: "Ik ga akkoord",
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{
				Type: irma.ActionSigning,
			},
			Disclose: irma.AttributeConDisCon{
				irma.AttributeDisCon{
					irma.AttributeCon{
						irma.NewAttributeRequest("irma-demo.nuts.agb.agbcode"),
					},
				},
			},
		},
	}

	irmaServer, _ := GetIrmaServer(serviceConfig)
	_, knownSessionID, _ := irmaServer.StartSession(signatureRequest, func(result *irmaservercore.SessionResult) {
		logrus.Infof("session done, result: %s", irmaservercore.ToJson(result))
	})

	type fields struct {
		IrmaServer *irmaserver.Server
	}
	type args struct {
		id services.SessionID
	}
	irmaServer, _ = GetIrmaServer(serviceConfig)
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *services.SessionStatusResult
	}{
		{
			"for an unknown session, it returns nil",
			fields{irmaServer},
			args{"unknown sessionId"},
			nil,
		},
		{
			"for a known session it returns a status",
			fields{irmaServer},
			args{services.SessionID(knownSessionID)},
			&services.SessionStatusResult{
				irmaservercore.SessionResult{Token: knownSessionID, Status: irmaservercore.StatusInitialized, Type: irma.ActionSigning},
				"",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := IrmaMethod{
				IrmaSessionHandler: tt.fields.IrmaServer,
			}

			got, _ := v.SessionStatus(tt.args.id)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("IrmaMethod.SessionStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockIrmaClient struct {
	err           error
	sessionResult irmaservercore.SessionResult
}

func (m *mockIrmaClient) GetSessionResult(token string) *irmaservercore.SessionResult {
	if m.err != nil {
		return nil
	}
	return &m.sessionResult
}

func (m *mockIrmaClient) StartSession(request interface{}, handler irmaservercore.SessionHandler) (*irma.Qr, string, error) {
	if m.err != nil {
		return nil, "", m.err
	}

	return nil, "", nil
}

// tests using mocks
func TestDefaultValidator_SessionStatus2(t *testing.T) {
	serviceConfig := IrmaServiceConfig{
		IrmaConfigPath:            "../../../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	t.Run("correct contract with registry lookup", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		rMock := registryMock.NewMockRegistryClient(ctrl)
		cMock := cryptoMock.NewMockClient(ctrl)
		iMock := mockIrmaClient{
			sessionResult: irmaservercore.SessionResult{
				Token: "token",
				Signature: &irma.SignedMessage{
					Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens verpleeghuis De nootjes en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
				},
			},
		}

		irmaConfig, _ := GetIrmaConfig(serviceConfig)
		v := IrmaMethod{
			IrmaSessionHandler: &iMock,
			IrmaConfig:         irmaConfig,
			Crypto:             cMock,
			Registry:           rMock,
			ValidContracts:     contract.Contracts,
		}

		orgID := registryTest.OrganizationID("1")
		rMock.EXPECT().ReverseLookup("verpleeghuis De nootjes").Return(&db.Organization{Identifier: orgID}, nil)
		cMock.EXPECT().SignJWT(gomock.Any(), cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: orgID.String()})).Return("token", nil)

		s, err := v.SessionStatus(services.SessionID("known"))

		if !assert.Nil(t, err) || !assert.NotNil(t, s) {
			t.FailNow()
		}
		assert.Equal(t, "token", s.NutsAuthToken)
	})
}

func TestDefaultValidator_ValidateJwt(t *testing.T) {

	validator, cryptoInstance := defaultValidator(t)
	os.Setenv("NUTS_IDENTITY", registryTest.VendorID("1").String())

	t.Run("valid jwt", func(t *testing.T) {

		oldFunc := contract.NowFunc

		contract.NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			contract.NowFunc = oldFunc
		}()

		token := createJwt(cryptoInstance, organizationID, organizationID, testdata.ValidIrmaContract)
		actingParty := "Demo EHR"

		result, err := validator.ValidateJwt(string(token), actingParty)
		if assert.NoError(t, err) && assert.NotNil(t, result) {
			assert.Equal(t, services.ValidationState("VALID"), result.ValidationResult)
			assert.Equal(t, services.ContractFormat("irma"), result.ContractFormat)
			assert.Equal(t, map[string]string{"nuts.agb.agbcode": "00000007"}, result.DisclosedAttributes)
		}
	})

	t.Run("missing legalEntity", func(t *testing.T) {

		oldFunc := contract.NowFunc

		contract.NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			contract.NowFunc = oldFunc
		}()

		var payload services.NutsIdentityToken

		var claims map[string]interface{}
		jsonString, _ := json.Marshal(payload)
		_ = json.Unmarshal(jsonString, &claims)

		token, err := cryptoInstance.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: organizationID.String()}))
		if err != nil {
			t.FailNow()
		}

		actingParty := "Demo EHR"

		result, err := validator.ValidateJwt(token, actingParty)
		if assert.Nil(t, result) && assert.NotNil(t, err) {
			assert.EqualError(t, err, ErrLegalEntityNotProvided.Error())
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
		oldFunc := contract.NowFunc

		contract.NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			contract.NowFunc = oldFunc
		}()

		token := createJwt(cryptoInstance, organizationID, organizationID, testdata.ForgedIrmaContract)

		result, err := validator.ValidateJwt(string(token), "Demo EHR")

		if assert.NotNil(t, result) && assert.Nil(t, err) {
			assert.Equal(t, services.Invalid, result.ValidationResult)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		token := createJwt(cryptoInstance, registryTest.OrganizationID("wrong_issuer"), organizationID, testdata.ValidIrmaContract)

		result, err := validator.ValidateJwt(string(token), "Demo EHR")
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Equal(t, "urn:oid:2.16.840.1.113883.2.4.6.1:wrong_issuer: organization not found", err.Error())
	})

	t.Run("wrong scheme manager", func(t *testing.T) {
		oldFunc := contract.NowFunc

		contract.NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			contract.NowFunc = oldFunc
		}()

		os.Setenv("NUTS_STRICTMODE", "true")
		cfg := core.NutsConfig()
		if err := cfg.Load(&cobra.Command{}); err != nil {
			t.Fatal("not expected error", err)
		}

		if assert.True(t, core.NutsConfig().InStrictMode()) {
			token := createJwt(cryptoInstance, organizationID, organizationID, testdata.ValidIrmaContract)
			actingParty := "Demo EHR"
			result, err := validator.ValidateJwt(string(token), actingParty)
			if assert.NoError(t, err) && assert.NotNil(t, result) {
				assert.Equal(t, services.ValidationState("INVALID"), result.ValidationResult)
			}
		}
		os.Unsetenv("NUTS_STRICTMODE")

	})
}

func TestDefaultValidator_createJwt(t *testing.T) {
	t.Run("Create valid JWT", func(t *testing.T) {
		oldFunc := contract.NowFunc

		contract.NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-10-01T13:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			contract.NowFunc = oldFunc
		}()

		validator, _ := defaultValidator(t)

		var c = SignedIrmaContract{}
		_ = json.Unmarshal([]byte(testdata.ValidIrmaContract), &c.IrmaContract)

		tokenString, err := validator.CreateIdentityTokenFromIrmaContract(&c, organizationID)

		if assert.Nil(t, err) && assert.NotEmpty(t, tokenString) {
			result, err := validator.ValidateJwt(tokenString, "Demo EHR")
			if assert.NoError(t, err) && assert.NotNil(t, result) {
				assert.Equal(t, services.Valid, result.ValidationResult)
			}
		}
	})
}

func TestDefaultValidator_legalEntityFromContract(t *testing.T) {
	type TestContext struct {
		ctrl  *gomock.Controller
		v     IrmaMethod
		rMock *registryMock.MockRegistryClient
	}
	createContext := func(t *testing.T) TestContext {
		ctrl := gomock.NewController(t)
		rMock := registryMock.NewMockRegistryClient(ctrl)

		v := IrmaMethod{
			Registry: rMock,
		}

		return TestContext{ctrl: ctrl, v: v, rMock: rMock}
	}

	t.Run("Empty message returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		_, err := ctx.v.legalEntityFromContract(&SignedIrmaContract{IrmaContract: irma.SignedMessage{}, ContractTemplate: &contract.ContractTemplate{}})

		assert.NotNil(t, err)
		assert.Error(t, contract.ErrInvalidContractText, err)
	})

	t.Run("Missing legalEntity returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		_, err := ctx.v.legalEntityFromContract(&SignedIrmaContract{
			IrmaContract: irma.SignedMessage{
				Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens  en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
			},
			ContractTemplate: contract.Contracts["NL"]["BehandelaarLogin"]["v1"],
		})

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, contract.ErrInvalidContractText))
	})

	t.Run("Unknown legalEntity returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.rMock.EXPECT().ReverseLookup("UNKNOWN").Return(nil, db.ErrOrganizationNotFound)

		_, err := ctx.v.legalEntityFromContract(&SignedIrmaContract{
			IrmaContract: irma.SignedMessage{
				Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens UNKNOWN en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
			},
			ContractTemplate: contract.Contracts["NL"]["BehandelaarLogin"]["v1"],
		})

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, db.ErrOrganizationNotFound))
	})
}

func TestDefaultValidator_ParseAndValidateJwtBearerToken(t *testing.T) {
	t.Run("malformed access tokens", func(t *testing.T) {
		validator, _ := defaultValidator(t)

		response, err := validator.ParseAndValidateJwtBearerToken("foo")
		assert.Nil(t, response)
		assert.Equal(t, "token contains an invalid number of segments", err.Error())

		response, err = validator.ParseAndValidateJwtBearerToken("123.456.787")
		assert.Nil(t, response)
		assert.Equal(t, "invalid character '×' looking for beginning of value", err.Error())
	})

	t.Run("wrong signing algorithm", func(t *testing.T) {
		validator, _ := defaultValidator(t)
		// alg: HS256
		const invalidJwt = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MDAwMDAwMDAiLCJzdWIiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjE6MTI0ODEyNDgiLCJzaWQiOiJ1cm46b2lkOjIuMTYuODQwLjEuMTEzODgzLjIuNC42LjM6OTk5OTk5MCIsImF1ZCI6Imh0dHBzOi8vdGFyZ2V0X3Rva2VuX2VuZHBvaW50IiwidXNpIjoiYmFzZTY0IGVuY29kZWQgc2lnbmF0dXJlIiwiZXhwIjo0MDcwOTA4ODAwLCJpYXQiOjE1Nzg5MTA0ODEsImp0aSI6IjEyMy00NTYtNzg5In0.2_4bxKKsVspQ4QxXRG8m2mOnLbl-fFgSkEq_h8N9sNE"
		response, err := validator.ParseAndValidateJwtBearerToken(invalidJwt)
		assert.Nil(t, response)
		assert.Equal(t, "signing method HS256 is invalid", err.Error())
	})

	t.Run("missing issuer", func(t *testing.T) {
		validator, _ := defaultValidator(t)
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
		validator, _ := defaultValidator(t)
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
		validator, _ := defaultValidator(t)

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
		validator, _ := defaultValidator(t)

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
		validator, _ := defaultValidator(t)

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
			IdentityToken: "base64 encoded signature",
			SubjectID:     "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
			Scope:         "nuts-sso",
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

func createJwt(cryptoInstance crypto.Client, iss core.PartyID, sub core.PartyID, contractStr string) []byte {
	contract := SignedIrmaContract{}
	err := json.Unmarshal([]byte(contractStr), &contract.IrmaContract)
	if err != nil {
		panic(err)
	}

	encodedContract := base64.StdEncoding.EncodeToString([]byte(contractStr))

	var payload services.NutsIdentityToken
	payload.Issuer = iss.String()
	payload.Type = services.IrmaFormat
	payload.Subject = sub.String()
	payload.Signature = encodedContract

	jsonString, _ := json.Marshal(payload)
	var claims map[string]interface{}
	_ = json.Unmarshal(jsonString, &claims)

	tokenString, _ := cryptoInstance.SignJWT(claims, cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: sub.String()}))

	return []byte(tokenString)
}

var organizationID = registryTest.OrganizationID("00000001")
var otherOrganizationID = registryTest.OrganizationID("00000002")

// defaultValidator sets up a validator with a registry containing a single test organization.
// The method is a singleton and always returns the same instance
func defaultValidator(t *testing.T) (IrmaMethod, crypto.Client) {
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
	address := "localhost:1323"
	serviceConfig := IrmaServiceConfig{
		Address:                   address,
		IrmaSchemeManager:         "pbdf",
		SkipAutoUpdateIrmaSchemas: true,
		IrmaConfigPath:            path.Join(testDirectory, "auth", "irma"),
		//ActingPartyCn:             "CN=Awesomesoft",
		PublicUrl: "http://" + address,
	}
	if err := os.MkdirAll(serviceConfig.IrmaConfigPath, 0777); err != nil {
		logrus.Fatal(err)
	}
	if err := test.CopyDir("../../../testdata/irma", serviceConfig.IrmaConfigPath); err != nil {
		logrus.Fatal(err)
	}
	serviceConfig.IrmaSchemeManager = "irma-demo"

	irmaConfig, err := GetIrmaConfig(serviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	return IrmaMethod{
		Registry:       testRegistry,
		Crypto:         testCrypto,
		IrmaConfig:     irmaConfig,
		ValidContracts: contract.Contracts,
	}, testCrypto
}

func TestDefaultValidator_BuildAccessToken(t *testing.T) {
	t.Run("missing subject", func(t *testing.T) {
		v, _ := defaultValidator(t)
		claims := &services.NutsJwtBearerToken{}
		identityValidationResult := &services.ContractValidationResult{ValidationResult: services.Valid}
		token, err := v.BuildAccessToken(claims, identityValidationResult)
		assert.Empty(t, token)
		assert.EqualError(t, err, "could not build accessToken: subject is missing")
	})

	t.Run("build an access token", func(t *testing.T) {
		v, _ := defaultValidator(t)
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
		v, _ := defaultValidator(t)
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
		v, _ := defaultValidator(t)

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
		v, _ := defaultValidator(t)

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
		v, _ := defaultValidator(t)

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
		SubjectID:     "urn:oid:2.16.840.1.113883.2.4.6.3:9999990",
		IdentityToken: "base64 encoded identity ",
		Scope:         "nuts-sso",
	}

	userIdentityValidationResult := services.ContractValidationResult{
		ValidationResult:    services.Valid,
		ContractFormat:      "",
		DisclosedAttributes: map[string]string{"nuts.agb.agbcode": "1234"},
	}

	t.Run("token not issued by care provider of this node", func(t *testing.T) {

		v, _ := defaultValidator(t)

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
		v, _ := defaultValidator(t)
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
