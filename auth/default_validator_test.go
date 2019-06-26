package auth

import (
	"encoding/base64"
	"github.com/nuts-foundation/nuts-auth/pkg"
	irma2 "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"reflect"
	"testing"
	"time"

	"github.com/nuts-foundation/nuts-auth/configuration"
	"github.com/nuts-foundation/nuts-auth/testdata"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

func TestValidateContract(t *testing.T) {
	type args struct {
		contract      string
		format        pkg.ContractFormat
		actingPartyCN string
	}
	location, _ := time.LoadLocation("Europe/Amsterdam")
	tests := []struct {
		name    string
		args    args
		date    time.Time
		want    *pkg.ValidationResponse
		wantErr bool
	}{
		{
			"a valid contract should be valid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				pkg.IrmaFormat,
				"Helder",
			},
			// contract is valid from 26 april 2019 11:45:30
			time.Date(2019, time.April, 26, 11, 46, 00, 0, location),
			&pkg.ValidationResponse{
				pkg.Valid,
				pkg.IrmaFormat,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000001"},
			},
			false,
		},
		{
			"a valid contract with the wrong actingPartyCn is invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				pkg.IrmaFormat,
				"Awesome ECD!!",
			},
			// contract is valid from 26 april 2019 11:45:30
			time.Date(2019, time.April, 26, 11, 46, 00, 0, location),
			&pkg.ValidationResponse{
				pkg.Invalid,
				pkg.IrmaFormat,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000001"},
			},
			false,
		},
		{
			"a valid contract without a provided actingParty returns an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				pkg.IrmaFormat,
				"",
			},
			// contract is valid from 26 april 2019 11:45:30
			time.Date(2019, time.April, 26, 11, 46, 00, 0, location),
			nil,
			true,
		},
		{
			"an expired contract should be invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				pkg.IrmaFormat,
				"Helder",
			},
			// contract is valid from 26 april 2019 11:45:30
			time.Date(2019, time.April, 27, 11, 46, 00, 0, location),
			&pkg.ValidationResponse{
				pkg.Invalid,
				pkg.IrmaFormat,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000001"},
			},
			false,
		},
		{
			"a forged contract it should be invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ForgedIrmaContract)),
				pkg.IrmaFormat,
				"Helder",
			},
			// contract is valid from 26 april 2019 11:45:30
			time.Date(2019, time.April, 27, 11, 46, 00, 0, location),
			&pkg.ValidationResponse{
				pkg.Invalid,
				pkg.IrmaFormat,
				map[string]string{},
			},
			false,
		},
		{
			"a valid but unknown contract should give an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidUnknownIrmaContract)),
				pkg.IrmaFormat,
				"Helder",
			},
			// contract is valid from 1 mei 2019 16:47:52
			time.Date(2019, time.May, 1, 16, 50, 00, 0, location),
			nil,
			true,
		},
		{
			"a valid json string which is not a contract should give an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.InvalidContract)),
				pkg.IrmaFormat,
				"Helder",
			},
			time.Now(), // the contract does not have a valid date
			nil,
			true,
		},
		{
			"a random string should give an error",
			args{
				base64.StdEncoding.EncodeToString([]byte("some string which is not json")),
				pkg.IrmaFormat,
				"Helder",
			},
			time.Now(), // the contract does not have a valid date
			nil,
			true,
		},
		{
			"an invalid base64 contract should give an error",
			args{
				"invalid base64",
				pkg.IrmaFormat,
				"Helder",
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
			},
			time.Now(), // the contract does not have a valid date
			nil,
			true,
		},
	}
	_ = configuration.Initialize("../testdata", "testconfig")
	pkg.GetIrmaConfig()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//patch := monkey.Patch(time.Now, func() time.Time { return tt.date })
			NowFunc = func() time.Time { return tt.date }
			//defer patch.Unpatch()
			got, err := pkg.DefaultValidator{IrmaServer: pkg.GetIrmaServer()}.ValidateContract(tt.args.contract, tt.args.format, tt.args.actingPartyCN)
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
	_ = configuration.Initialize("../testdata", "testconfig")
	pkg.GetIrmaConfig()

	signatureRequest := &irma2.SignatureRequest{
		Message: "Ik ga akkoord",
		DisclosureRequest: irma2.DisclosureRequest{
			BaseRequest: irma2.BaseRequest{
				Type: irma2.ActionSigning,
			},
			Content: irma2.AttributeDisjunctionList([]*irma2.AttributeDisjunction{{
				Label:      "AGB-Code",
				Attributes: []irma2.AttributeTypeIdentifier{irma2.NewAttributeTypeIdentifier("irma-demo.nuts.agb.agbcode")},
			}}),
		},
	}

	_, knownSessionId, _ := pkg.GetIrmaServer().StartSession(signatureRequest, func(result *server.SessionResult) {
		logrus.Infof("session done, result: %s", server.ToJson(result))
	})

	type fields struct {
		IrmaServer *irmaserver.Server
	}
	type args struct {
		id pkg.SessionId
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   *pkg.SessionStatusResult
	}{
		{
			"for an unknown session, it returns nil",
			fields{pkg.GetIrmaServer()},
			args{"unknown sessionId"},
			nil,
		},
		{
			"for a known session it returns a status",
			fields{pkg.GetIrmaServer()},
			args{pkg.SessionId(knownSessionId)},
			&pkg.SessionStatusResult{
				server.SessionResult{Token: knownSessionId, Status: server.StatusInitialized, Type: irma2.ActionSigning,},
				"",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := pkg.DefaultValidator{
				IrmaServer: tt.fields.IrmaServer,
			}
			if got := v.SessionStatus(tt.args.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultValidator.SessionStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}
