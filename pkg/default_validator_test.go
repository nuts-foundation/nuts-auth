package pkg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"github.com/nuts-foundation/nuts-registry/pkg/events"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

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
		v := DefaultValidator{irmaConfig: &irma2.Configuration{}}
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
		want    *ValidationResult
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
			&ValidationResult{
				Valid,
				IrmaFormat,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000007"},
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
			&ValidationResult{
				Invalid,
				IrmaFormat,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000007"},
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
			&ValidationResult{
				Invalid,
				IrmaFormat,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000007"},
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
			&ValidationResult{
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

	validator := DefaultValidator{IrmaServer: GetIrmaServer(authConfig), irmaConfig: GetIrmaConfig(authConfig)}

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
			irmaConfig: GetIrmaConfig(authConfig),
			crypto:     cMock,
			registry:   rMock,
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

		token := createJwt("nuts", "urn:oid:2.16.840.1.113883.2.4.6.1:00000000", testdata.ValidIrmaContract)
		actingParty := "Demo EHR"

		result, err := validator.ValidateJwt(string(token), actingParty)
		if assert.Nil(t, err) && assert.NotNil(t, result) {
			assert.Equal(t, ValidationState("VALID"), result.ValidationResult)
			assert.Equal(t, ContractFormat("irma"), result.ContractFormat)
			assert.Equal(t, map[string]string{"irma-demo.nuts.agb.agbcode": "00000007"}, result.DisclosedAttributes)
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

		var payload nutsJwt

		payload.Issuer = "nuts"
		payload.Contract = SignedIrmaContract{}

		_ = json.Unmarshal([]byte(testdata.ValidIrmaContract), &payload.Contract.IrmaContract)

		var claims map[string]interface{}
		jsonString, _ := json.Marshal(payload)
		_ = json.Unmarshal(jsonString, &claims)

		token, _ := cryptoInstance.SignJwtFor(claims, types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"})
		actingParty := "Demo EHR"

		result, err := validator.ValidateJwt(token, actingParty)
		if assert.Nil(t, result) && assert.NotNil(t, err) {
			assert.True(t, strings.Contains(err.Error(), ErrLegalEntityNotFound.Error())) // jwt-go does not use Go 1.13 errors yet
		}
	})

	t.Run("invalid formatted jwt", func(t *testing.T) {
		token := "foo.bar.sig"

		result, err := validator.ValidateJwt(token, "actingParty")

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.EqualError(t, err, "could not parse jwt: invalid character '~' looking for beginning of value")
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

		token := createJwt("nuts", "urn:oid:2.16.840.1.113883.2.4.6.1:00000000", testdata.ForgedIrmaContract)
		//token = append(token[:len(token)-1], byte('a'))

		result, err := validator.ValidateJwt(string(token), "Demo EHR")

		if assert.NotNil(t, result) && assert.Nil(t, err) {
			assert.Equal(t, Invalid, result.ValidationResult)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		token := createJwt("wrong_issuer", "urn:oid:2.16.840.1.113883.2.4.6.1:00000000", testdata.ValidIrmaContract)

		result, err := validator.ValidateJwt(string(token), "Demo EHR")
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidContract))
		assert.Equal(t, "jwt does not have the nuts issuer: invalid contract", err.Error())
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
			token := createJwt("nuts", "urn:oid:2.16.840.1.113883.2.4.6.1:00000000", testdata.ValidIrmaContract)
			actingParty := "Demo EHR"
			result, err := validator.ValidateJwt(string(token), actingParty)
			if assert.Nil(t, err) && assert.NotNil(t, result) {
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
		//defer os.RemoveAll(cryptoInstance.Config.Fspath)

		var c = SignedIrmaContract{}
		_ = json.Unmarshal([]byte(testdata.ValidIrmaContract), &c.IrmaContract)

		tokenString, err := validator.createJwt(&c, "urn:oid:2.16.840.1.113883.2.4.6.1:00000000")

		if assert.Nil(t, err) && assert.NotEmpty(t, tokenString) {
			result, err := validator.ValidateJwt(tokenString, "Demo EHR")
			if assert.Nil(t, err) && assert.NotNil(t, result) {
				assert.Equal(t, Valid, result.ValidationResult)
			}
		}
	})
}

func TestDefaultValidator_legalEntityFromContract(t *testing.T) {
	ctrl := gomock.NewController(t)
	rMock := registryMock.NewMockRegistryClient(ctrl)

	v := DefaultValidator{
		registry: rMock,
	}

	t.Run("Empty message returns error", func(t *testing.T) {
		_, err := v.legalEntityFromContract(SignedIrmaContract{IrmaContract: irma2.SignedMessage{}})

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrInvalidContractText))
	})

	t.Run("Missing legalEntity returns error", func(t *testing.T) {
		_, err := v.legalEntityFromContract(SignedIrmaContract{
			IrmaContract: irma2.SignedMessage{
				Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens  en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
			},
		})

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, ErrInvalidContractText))
	})

	t.Run("Unknown legalEntity returns error", func(t *testing.T) {
		rMock.EXPECT().ReverseLookup("UNKNOWN").Return(nil, db.ErrOrganizationNotFound)

		_, err := v.legalEntityFromContract(SignedIrmaContract{
			IrmaContract: irma2.SignedMessage{
				Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens UNKNOWN en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
			},
		})

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, db.ErrOrganizationNotFound))
	})
}

func createJwt(iss string, sub string, irmaContract string) []byte {
	var payload nutsJwt

	payload.Issuer = iss
	payload.Subject = sub
	payload.Contract = SignedIrmaContract{}

	_ = json.Unmarshal([]byte(irmaContract), &payload.Contract.IrmaContract)

	var claims map[string]interface{}
	jsonString, _ := json.Marshal(payload)
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

func defaultValidator() DefaultValidator {
	mutex := sync.Mutex{}
	mutex.Lock()
	defer mutex.Unlock()

	if testInstance == nil {

		r := registry.RegistryInstance()
		r.Config.Mode = core.ServerEngineMode
		r.Config.Datadir = "tmp"
		r.Config.SyncMode = "fs"
		if err := r.Configure(); err != nil {
			panic(err)
		}

		if err := cryptoInstance.Configure(); err != nil {
			panic(err)
		}
		_ = cryptoInstance.GenerateKeyPairFor(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"})
		{
			vendorEvent, err := events.CreateEvent(events.RegisterVendor, events.RegisterVendorEvent{
				Identifier: "1",
				Name:       "BecauseWeCare Software",
			})
			if err != nil {
				panic(err)
			}
			if err := r.EventSystem.PublishEvent(vendorEvent); err != nil {
				panic(err)
			}
		}
		{
			le := types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"}
			_ = cryptoInstance.GenerateKeyPairFor(le)
			pub, _ := cryptoInstance.PublicKeyInJWK(le)
			pubJwkAsMap, _ := crypto.JwkToMap(pub)
			claimEvent, err := events.CreateEvent(events.VendorClaim, events.VendorClaimEvent{
				VendorIdentifier: "1",
				OrgIdentifier:    "urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
				OrgName:          "verpleeghuis De nootjes",
				OrgKeys:          []interface{}{pubJwkAsMap},
			})
			if err != nil {
				panic(err)
			}
			if err := r.EventSystem.PublishEvent(claimEvent); err != nil {
				panic(err)
			}
		}

		testInstance = &DefaultValidator{
			registry: r,
			crypto:   cryptoInstance,
			irmaConfig: GetIrmaConfig(AuthConfig{
				IrmaConfigPath:            "../testdata/irma",
				SkipAutoUpdateIrmaSchemas: true,
			}),
		}
	}

	return *testInstance
}
