package pkg

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
	"github.com/stretchr/testify/assert"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-auth/testdata"
	irma2 "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

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
		IrmaConfigPath: "../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	validator := DefaultValidator{IrmaServer: GetIrmaServer(authConfig), irmaConfig:GetIrmaConfig(authConfig)}

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
		IrmaConfigPath: "../testdata/irma",
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
			if got := v.SessionStatus(tt.args.id, ""); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultValidator.SessionStatus() = %v, want %v", got, tt.want)
			}
		})
	}
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

	t.Run("invalid formatted jwt", func(t *testing.T) {
		token := "foo.bar"

		result, err := validator.ValidateJwt(token, "actingParty")

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidContract))
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

		result, _ := validator.ValidateJwt(string(token), "Demo EHR")

		//if assert.NotNil(t, result) && assert.NotNil(t, err) {
			assert.Equal(t, Invalid, result.ValidationResult)
		//}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		token := createJwt("wrong_issuer", "urn:oid:2.16.840.1.113883.2.4.6.1:00000000", testdata.ValidIrmaContract)

		result, err := validator.ValidateJwt(string(token), "Demo EHR")
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.True(t, errors.Is(err, ErrInvalidContract))
		assert.Equal(t, "jwt does not have the nuts issuer: invalid contract", err.Error())
	})

	t.Run("wrong legalEntity", func(t *testing.T) {
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

		token := createJwt("nuts", "urn:oid:2.16.840.1.113883.2.4.6.1:00000001", testdata.ValidIrmaContract)

		result, err := validator.ValidateJwt(string(token), "Demo EHR")
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.Equal(t, "could not verify jwt: organization not found", err.Error())
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
		json.Unmarshal([]byte(testdata.ValidIrmaContract), &c.IrmaContract)

		tokenString, err := validator.createJwt(&c, "urn:oid:2.16.840.1.113883.2.4.6.1:00000000")

		if assert.Nil(t, err) && assert.NotEmpty(t, tokenString) {
			result, err := validator.ValidateJwt(tokenString, "Demo EHR")
			if assert.Nil(t, err) && assert.NotNil(t, result) {
				assert.Equal(t, Valid, result.ValidationResult)
			}
		}
	})
}

func createJwt(iss string, sub string, irmaContract string) []byte {
	var payload nutsJwt

	payload.Issuer = iss
	payload.Subject = sub
	payload.Contract = SignedIrmaContract{}

	json.Unmarshal([]byte(irmaContract), &payload.Contract.IrmaContract)

	var claims map[string]interface{}
	jsonString, _ := json.Marshal(payload)
	json.Unmarshal(jsonString, &claims)

	tokenString, _ := cryptoInstance.SignJwtFor(claims, types.LegalEntity{URI:sub})

	return []byte(tokenString)
}

var cryptoInstance = &crypto.Crypto{
	Config: crypto.CryptoConfig{
		Keysize: types.ConfigKeySizeDefault,
		Fspath: "../testdata/tmp",
	},
}
var testInstance *DefaultValidator

func defaultValidator() DefaultValidator {
	mutex := sync.Mutex{}
	mutex.Lock()
	defer mutex.Unlock()

	if testInstance == nil {

		r := registry.RegistryInstance()
		r.Config.Mode = "server"
		r.Config.Datadir = "tmp"
		r.Config.SyncMode = "fs"
		if err := r.Configure(); err != nil {
			panic(err)
		}

		if err := cryptoInstance.Configure(); err != nil {
			panic(err)
		}

		le := types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"}
		cryptoInstance.GenerateKeyPairFor(le)
		cryptoInstance.GenerateKeyPairFor(types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000001"})
		pub, _ := cryptoInstance.PublicKey(le)

		r.RegisterOrganization(db.Organization{
			Identifier: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
			Name:       "verpleeghuis De nootjes",
			PublicKey:  &pub,
		})

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