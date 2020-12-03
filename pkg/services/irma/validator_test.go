package irma

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path"
	"reflect"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-auth/logging"

	"github.com/nuts-foundation/nuts-auth/pkg/services"

	registry "github.com/nuts-foundation/nuts-registry/pkg"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"

	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-go-test/io"

	"github.com/nuts-foundation/nuts-auth/test"

	registryTest "github.com/nuts-foundation/nuts-registry/test"

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
	"github.com/privacybydesign/irmago/server/irmaserver"
)

func TestDefaultValidator_IsInitialized(t *testing.T) {
	t.Run("No irma config returns false", func(t *testing.T) {
		v := Service{}
		assert.False(t, v.IsInitialized())
	})

	t.Run("with irma config returns true", func(t *testing.T) {
		v := Service{IrmaConfig: &irma.Configuration{}}
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
	location, _ := time.LoadLocation(contract.AmsterdamTimeZone)
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
				ValidationResult:    services.Valid,
				ContractFormat:      services.IrmaFormat,
				DisclosedAttributes: map[string]string{"nuts.agb.agbcode": "00000007"},
				ContractAttributes:  map[string]string{"legal_entity": "verpleeghuis De nootjes", "acting_party": "Demo EHR", "valid_from": "dinsdag, 1 oktober 2019 13:30:42", "valid_to": "dinsdag, 1 oktober 2019 14:30:42"},
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
				ValidationResult:    services.Invalid,
				ContractFormat:      services.IrmaFormat,
				DisclosedAttributes: map[string]string{"nuts.agb.agbcode": "00000007"},
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
				ValidationResult:    services.Invalid,
				ContractFormat:      services.IrmaFormat,
				DisclosedAttributes: map[string]string{"nuts.agb.agbcode": "00000007"},
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
				ValidationResult:    services.Invalid,
				ContractFormat:      services.IrmaFormat,
				DisclosedAttributes: nil,
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

	authConfig := ValidatorConfig{
		IrmaConfigPath:            "../../../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	irmaConfig, _ := GetIrmaConfig(authConfig)
	irmaServer, _ := GetIrmaServer(authConfig)
	validator := Service{IrmaSessionHandler: irmaServer, IrmaConfig: irmaConfig, ContractTemplates: contract.StandardContractTemplates}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contract.NowFunc = func() time.Time { return tt.date }
			got, err := validator.ValidateContract(tt.args.contract, tt.args.format, &tt.args.actingPartyCN)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateContractV0() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ValidateContractV0() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultValidator_SessionStatus(t *testing.T) {
	serviceConfig := ValidatorConfig{
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
		logging.Log().Infof("session done, result: %s", irmaservercore.ToJson(result))
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
			v := Service{
				IrmaSessionHandler: tt.fields.IrmaServer,
			}

			got, _ := v.SessionStatus(tt.args.id)

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Service.SessionStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

type mockIrmaClient struct {
	err           error
	sessionResult *irmaservercore.SessionResult
	irmaQr        *irma.Qr
	sessionToken  string
}

func (m *mockIrmaClient) GetSessionResult(token string) *irmaservercore.SessionResult {
	if m.err != nil {
		return nil
	}
	return m.sessionResult
}

func (m *mockIrmaClient) StartSession(request interface{}, handler irmaservercore.SessionHandler) (*irma.Qr, string, error) {
	if m.err != nil {
		return nil, "", m.err
	}

	return m.irmaQr, m.sessionToken, nil
}

// tests using mocks
func TestDefaultValidator_SessionStatus2(t *testing.T) {
	serviceConfig := ValidatorConfig{
		IrmaConfigPath:            "../../../testdata/irma",
		SkipAutoUpdateIrmaSchemas: true,
	}

	t.Run("correct contract with registry lookup", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		rMock := registryMock.NewMockRegistryClient(ctrl)
		cMock := cryptoMock.NewMockClient(ctrl)
		iMock := mockIrmaClient{
			sessionResult: &irmaservercore.SessionResult{
				Token: "token",
				Signature: &irma.SignedMessage{
					Message: "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens verpleeghuis De nootjes en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42.",
				},
			},
		}

		irmaConfig, _ := GetIrmaConfig(serviceConfig)
		v := Service{
			IrmaSessionHandler: &iMock,
			IrmaConfig:         irmaConfig,
			Crypto:             cMock,
			Registry:           rMock,
			ContractTemplates:  contract.StandardContractTemplates,
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

		result, err := validator.ValidateJwt(string(token), &actingParty)
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

		result, err := validator.ValidateJwt(token, &actingParty)
		if assert.Nil(t, result) && assert.NotNil(t, err) {
			assert.EqualError(t, err, ErrLegalEntityNotProvided.Error())
		}
	})

	t.Run("invalid formatted jwt", func(t *testing.T) {
		token := "foo.bar.sig"

		result, err := validator.ValidateJwt(token, nil)

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

		result, err := validator.ValidateJwt(string(token), nil)

		if assert.NotNil(t, result) && assert.Nil(t, err) {
			assert.Equal(t, services.Invalid, result.ValidationResult)
		}
	})

	t.Run("wrong issuer", func(t *testing.T) {
		token := createJwt(cryptoInstance, registryTest.OrganizationID("wrong_issuer"), organizationID, testdata.ValidIrmaContract)

		result, err := validator.ValidateJwt(string(token), nil)
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
			result, err := validator.ValidateJwt(string(token), &actingParty)
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
			actingPartyCN := "Demo EHR"
			result, err := validator.ValidateJwt(tokenString, &actingPartyCN)
			if assert.NoError(t, err) && assert.NotNil(t, result) {
				assert.Equal(t, services.Valid, result.ValidationResult)
			}
		}
	})
}

func TestDefaultValidator_legalEntityFromContract(t *testing.T) {
	type TestContext struct {
		ctrl  *gomock.Controller
		v     Service
		rMock *registryMock.MockRegistryClient
	}
	createContext := func(t *testing.T) TestContext {
		ctrl := gomock.NewController(t)
		rMock := registryMock.NewMockRegistryClient(ctrl)

		v := Service{
			Registry: rMock,
		}

		return TestContext{ctrl: ctrl, v: v, rMock: rMock}
	}

	t.Run("Empty message returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		_, err := ctx.v.legalEntityFromContract(&SignedIrmaContract{IrmaContract: irma.SignedMessage{}, Contract: &contract.Contract{}})

		assert.NotNil(t, err)
		assert.Error(t, contract.ErrInvalidContractText, err)
	})

	t.Run("Missing legalEntity returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()
		rawText := "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens  en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42."
		signedContract, err := contract.ParseContractString(rawText, contract.StandardContractTemplates)

		assert.Nil(t, signedContract)
		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, contract.ErrInvalidContractText))
	})

	t.Run("Unknown legalEntity returns error", func(t *testing.T) {
		ctx := createContext(t)
		defer ctx.ctrl.Finish()

		ctx.rMock.EXPECT().ReverseLookup("UNKNOWN").Return(nil, db.ErrOrganizationNotFound)

		rawText := "NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan Demo EHR om namens UNKNOWN en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van dinsdag, 1 oktober 2019 13:30:42 tot dinsdag, 1 oktober 2019 14:30:42."
		signedContract, err := contract.ParseContractString(rawText, contract.StandardContractTemplates)

		assert.Nil(t, err)

		_, err = ctx.v.legalEntityFromContract(&SignedIrmaContract{
			Contract: signedContract,
		})

		assert.NotNil(t, err)
		assert.True(t, errors.Is(err, db.ErrOrganizationNotFound))
	})
}

func TestService_VerifyVP(t *testing.T) {
	t.Run("ok - valid VP", func(t *testing.T) {
		validator, _ := defaultValidator(t)

		irmaSignature := testdata.ValidIrmaContract
		validIrmaContract := irma.SignedMessage{}
		err := json.Unmarshal([]byte(irmaSignature), &validIrmaContract)
		if !assert.NoError(t, err) {
			return
		}

		rawSic, err := json.Marshal(validIrmaContract)

		vp := VerifiablePresentation{
			Proof: VPProof{
				Proof:     contract.Proof{Type: ""},
				Signature: string(rawSic),
			},
		}

		rawIrmaVP, err := json.Marshal(vp)
		if !assert.NoError(t, err) {
			return
		}
		validationResult, err := validator.VerifyVP(rawIrmaVP)

		if !assert.NoError(t, err) {
			return
		}

		if !assert.NotNil(t, validationResult) {
			return
		}
	})

	t.Run("nok - invalid rawVP", func(t *testing.T) {
		validator := Service{}
		validationResult, err := validator.VerifyVP([]byte{})

		assert.Nil(t, validationResult)
		if !assert.Error(t, err) {
			return
		}
		assert.Equal(t, "could not verify VP: unexpected end of JSON input", err.Error())

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
func defaultValidator(t *testing.T) (Service, crypto.Client) {
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
	serviceConfig := ValidatorConfig{
		Address:                   address,
		IrmaSchemeManager:         "pbdf",
		SkipAutoUpdateIrmaSchemas: true,
		IrmaConfigPath:            path.Join(testDirectory, "auth", "irma"),
		//ActingPartyCn:             "CN=Awesomesoft",
		PublicURL: "http://" + address,
	}
	if err := os.MkdirAll(serviceConfig.IrmaConfigPath, 0777); err != nil {
		logging.Log().Fatal(err)
	}
	if err := test.CopyDir("../../../testdata/irma", serviceConfig.IrmaConfigPath); err != nil {
		logging.Log().Fatal(err)
	}
	serviceConfig.IrmaSchemeManager = "irma-demo"

	irmaConfig, err := GetIrmaConfig(serviceConfig)
	if err != nil {
		t.Fatal(err)
	}
	return Service{
		Registry:          testRegistry,
		Crypto:            testCrypto,
		IrmaConfig:        irmaConfig,
		ContractTemplates: contract.StandardContractTemplates,
	}, testCrypto
}
