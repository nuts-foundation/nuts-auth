package pkg

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"golang.org/x/xerrors"
	"reflect"
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
				"Helder",
			},
			// contract is valid from 26 april 2019 11:45:30
			time.Date(2019, time.April, 26, 11, 46, 00, 0, location),
			&ValidationResult{
				Valid,
				IrmaFormat,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000001"},
			},
			false,
		},
		{
			"a valid contract with the wrong actingPartyCn is invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				IrmaFormat,
				"Awesome ECD!!",
			},
			// contract is valid from 26 april 2019 11:45:30
			time.Date(2019, time.April, 26, 11, 46, 00, 0, location),
			&ValidationResult{
				Invalid,
				IrmaFormat,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000001"},
			},
			false,
		},
		{
			"a valid contract without a provided actingParty returns an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				IrmaFormat,
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
				IrmaFormat,
				"Helder",
			},
			// contract is valid from 26 april 2019 11:45:30
			time.Date(2019, time.April, 27, 11, 46, 00, 0, location),
			&ValidationResult{
				Invalid,
				IrmaFormat,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000001"},
			},
			false,
		},
		{
			"a forged contract it should be invalid",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ForgedIrmaContract)),
				IrmaFormat,
				"Helder",
			},
			// contract is valid from 26 april 2019 11:45:30
			time.Date(2019, time.April, 27, 11, 46, 00, 0, location),
			&ValidationResult{
				Invalid,
				IrmaFormat,
				map[string]string{},
			},
			false,
		},
		{
			"a valid but unknown contract should give an error",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidUnknownIrmaContract)),
				IrmaFormat,
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
				IrmaFormat,
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
				IrmaFormat,
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
				IrmaFormat,
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
	GetIrmaConfig(AuthConfig{})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			//patch := monkey.Patch(time.Now, func() time.Time { return tt.date })
			NowFunc = func() time.Time { return tt.date }
			//defer patch.Unpatch()
			got, err := DefaultValidator{IrmaServer: GetIrmaServer(AuthConfig{})}.ValidateContract(tt.args.contract, tt.args.format, tt.args.actingPartyCN)
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
	GetIrmaConfig(AuthConfig{})

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

	_, knownSessionID, _ := GetIrmaServer(AuthConfig{}).StartSession(signatureRequest, func(result *server.SessionResult) {
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
			fields{GetIrmaServer(AuthConfig{})},
			args{"unknown sessionId"},
			nil,
		},
		{
			"for a known session it returns a status",
			fields{GetIrmaServer(AuthConfig{})},
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
			if got := v.SessionStatus(tt.args.id); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("DefaultValidator.SessionStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDefaultValidator_ValidateJwt(t *testing.T) {

	t.Run("valid jwt", func(t *testing.T) {

		oldFunc := NowFunc

		NowFunc = func() time.Time {
			now, err := time.Parse(time.RFC3339, "2019-07-01T14:38:45+02:00")
			if err != nil {
				panic(err)
			}
			return now
		}
		defer func() {
			NowFunc = oldFunc
		}()

		validator := DefaultValidator{}

		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJudXRzIiwibnV0c19zaWduYXR1cmUiOnsiSXJtYUNvbnRyYWN0Ijp7InNpZ25hdHVyZSI6W3siYyI6IlAwdzFWSXlsR3Eycm1NZms2NW9wektsQXNkUkY2RGFFR2JzamZFWlhLWnc9IiwiQSI6IjAzQTVacy9FNk96Y2xNZWhWenhnQ2ZWRU42LzVEelpZRGNUMG9FeURuMWNpNW8wSi9mS1dUa0VWUW1xU3J5R284eVNLaDhLbWFoZElOSTA5Y0t6THBHNmpaVTVtMkZFcDRMcDMxQXhnMUQ3WURCRjIwZ1BnL1crUU5UVXZZQXFVWTJNRzIwL1hVUmRGa3lqWkJieFhhaUxFWjlLT0Y2bU9XQmtqSWRpUW52Q1hiUjJ0T1RzbFpHR1R5TkpadlkrQnhvMW5Nb0VheXNrTFlrS1RUcm1Ic080SmUrM01RSk9SZDhSS29sQUM3R2pIM0h6amhsenQ3enp3WEc2anFwTEFVQ1hXRDBGdnhKQWpRSmltOVdOY003ZTVVM2dKS04yU1hhTjJPbUxCdHo2amVHUW1abjRJbDlkV1oyOVloQXFsa3F1QlFvYzBNTXRHTC91Vm9RaXBhdz09IiwiZV9yZXNwb25zZSI6IkV5YWRGOWtOeE16cGVhdWxzeU1tdlorU3VtY3owbE5tVGFKYjdLV0pUVDBRQ2lGTWNpOGQyNElPSFptWEUxOFhKSHR3ZW1lN2xHZE00VUhHOXEweSIsInZfcmVzcG9uc2UiOiJEeTlFUnpkMHEwR04zM3N2MTlUdUl2T3orWW9CU21RQmNZRU1yNzNhWXpkaDRmVDZGanRVVkRrdFI0WTdFNERMbXhIT0ttSjJrSG1UQmxCSHVEUHZxK0d0MkJRSGN5b3R1aEc3dkV3ZDhjOHVYbW9zcTVTWmI2ZVQwTHN0djJaWDNnc3dLYUhlcngvVm9qL2Z3VWswdzRXejl6RDdxaWYvK3d2WmFQNDVvaFQ4YXh2andtQWo3Y3pMUlFrUDdKL29vOGVMSWlaR1J2WVFZb0ZDeWxVNXpJQ0dad2hCSWhUOHZVd1FmR1owRGxsL2dTU0wrSXdIYVdYYi96UkVDWDNBWUIxQVNQbVVteElBaWhYU3RTREhCZ0JudlkvMnpZa0grTC9pWVd3eGtSS0F5aTJXd2MvNEZGSmFkOU4zZExOSGR2L3d4MENGUmRjSGMwWDhKSk11T3VqYjZsa0U2NEpHNkhyWDZ3Kys1ay90T05RTnlUS0VLNjZzQ3NFTEYzU3N3ekpEbkJCMjhJd09QaXpqajNLdzBvZCtZNlpwOCtFa0hpTzBBTmVETEhRV0tqSUY4MEFmNHgwVEdZSUtMZ214aXBTeVAzZWhMbWdnbWZyWjduSkdxSG1RdmZKSW1FalU3OXpCdHBjVUhROWxZZnk0TU4vRXhFa3NoTG9lbU5MUWJrSWRqTExuczd1Z2dnS2VXY1RvanZnPSIsImFfcmVzcG9uc2VzIjp7IjAiOiJRREpiYXA1REJjL3ExbkFjcDJzb2FEYkhJYklSN245RmFoU0tlVUFVdWI5N0hCOTZrK2NKbU5aUWRVSlpqdVU3eEdrTW8zNWdxTjRHdmVHSVJ6cnpsa21HMHExY1d1RHBaUUE9IiwiMyI6IkJGYnh1MmxSWVRxNm5PL2RxR1FSQTJhajA0ZnNIU25kQU9vbXRTWnN0VVpEMmo3QU5lTTN1dFhuMGNIekxPZ3pxcksra01TQndTRDlLY2xxZDk5M3NCV3cwUHVoWTVoZXdvQlI4SCsvVWhFPSJ9LCJhX2Rpc2Nsb3NlZCI6eyIxIjoiQXdBS0N3QWFBQUJIMmprbFV0czVpQldTbEtMaE1qdmkiLCIyIjoiWUdCZ1lHQmdZR009In19XSwiaW5kaWNlcyI6W1t7ImNyZWQiOjAsImF0dHIiOjJ9XV0sIm5vbmNlIjoieWUvTjRKNGM1ZG5MalNCZTNvaEdSQT09IiwiY29udGV4dCI6IkFRPT0iLCJtZXNzYWdlIjoiTkw6QmVoYW5kZWxhYXJMb2dpbjp2MSBPbmRlcmdldGVrZW5kZSBnZWVmdCB0b2VzdGVtbWluZyBhYW4gRGVtbyBFSFIgb20gdWl0IHppam4vaGFhciBuYWFtIGhldCBOdXRzIG5ldHdlcmsgdGUgYmV2cmFnZW4uIERlemUgdG9lc3RlbW1pbmcgaXMgZ2VsZGlnIHZhbiBtYWFuZGFnLCAxIGp1bGkgMjAxOSAxNDozNjo0OSB0b3QgbWFhbmRhZywgMSBqdWxpIDIwMTkgMTU6MzY6NDkuIiwidGltZXN0YW1wIjp7IlRpbWUiOjE1NjE5ODQ2NDYsIlNlcnZlclVybCI6Imh0dHBzOi8vbWV0cmljcy5wcml2YWN5YnlkZXNpZ24uZm91bmRhdGlvbi9hdHVtIiwiU2lnIjp7IkFsZyI6ImVkMjU1MTkiLCJEYXRhIjoiNTl6dHhLRVViVnA3RTZTa1hjdWRrN3FlOUdKOWwrTE05NllacWxhd2x5dXdXSEhxZkg2a2ZRbjAvMHNUdnN6T3JydTlZUStLSm5SdXd1WGVXR1duQnc9PSIsIlB1YmxpY0tleSI6ImUvbk1BSkY3bndydk5aUnB1SmxqTnBSeCtDc1Q3Y2FhWHluOU9YNjgzUjg9In19fX19.zTV8pb71A8E-B3YOaY5zAJaMFlDN7fiV0bKJtAufeoA"
		actingParty := "Demo EHR"

		result, err := validator.ValidateJwt(token, actingParty)
		assert.Nil(t, err)
		assert.NotNil(t, result)
		assert.Equal(t, ValidationState("VALID"), result.ValidationResult)
		assert.Equal(t, ContractFormat("irma"), result.ContractFormat)
		assert.Equal(t, map[string]string(map[string]string{"irma-demo.nuts.agb.agbcode": "00000001"}), result.DisclosedAttributes)
	})

	t.Run("invalid formatted jwt", func(t *testing.T) {
		validator := DefaultValidator{}
		token := "foo.bar"

		result, err := validator.ValidateJwt(token, "actingParty")

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.True(t, xerrors.Is(err, ErrInvalidContract))
	})

	t.Run("invalid signature jwt", func(t *testing.T) {
		validator := DefaultValidator{}
		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJudXRzIIwibnV0c19zaWduYXR1cmUiOnsiSXJtYUNvbnRyYWN0Ijp7InNpZ25hdHVyZSI6W3siYyI6IlAwdzFWSXlsR3Eycm1NZms2NW9wektsQXNkUkY2RGFFR2JzamZFWlhLWnc9IiwiQSI6IjAzQTVacy9FNk96Y2xNZWhWenhnQ2ZWRU42LzVEelpZRGNUMG9FeURuMWNpNW8wSi9mS1dUa0VWUW1xU3J5R284eVNLaDhLbWFoZElOSTA5Y0t6THBHNmpaVTVtMkZFcDRMcDMxQXhnMUQ3WURCRjIwZ1BnL1crUU5UVXZZQXFVWTJNRzIwL1hVUmRGa3lqWkJieFhhaUxFWjlLT0Y2bU9XQmtqSWRpUW52Q1hiUjJ0T1RzbFpHR1R5TkpadlkrQnhvMW5Nb0VheXNrTFlrS1RUcm1Ic080SmUrM01RSk9SZDhSS29sQUM3R2pIM0h6amhsenQ3enp3WEc2anFwTEFVQ1hXRDBGdnhKQWpRSmltOVdOY003ZTVVM2dKS04yU1hhTjJPbUxCdHo2amVHUW1abjRJbDlkV1oyOVloQXFsa3F1QlFvYzBNTXRHTC91Vm9RaXBhdz09IiwiZV9yZXNwb25zZSI6IkV5YWRGOWtOeE16cGVhdWxzeU1tdlorU3VtY3owbE5tVGFKYjdLV0pUVDBRQ2lGTWNpOGQyNElPSFptWEUxOFhKSHR3ZW1lN2xHZE00VUhHOXEweSIsInZfcmVzcG9uc2UiOiJEeTlFUnpkMHEwR04zM3N2MTlUdUl2T3orWW9CU21RQmNZRU1yNzNhWXpkaDRmVDZGanRVVkRrdFI0WTdFNERMbXhIT0ttSjJrSG1UQmxCSHVEUHZxK0d0MkJRSGN5b3R1aEc3dkV3ZDhjOHVYbW9zcTVTWmI2ZVQwTHN0djJaWDNnc3dLYUhlcngvVm9qL2Z3VWswdzRXejl6RDdxaWYvK3d2WmFQNDVvaFQ4YXh2andtQWo3Y3pMUlFrUDdKL29vOGVMSWlaR1J2WVFZb0ZDeWxVNXpJQ0dad2hCSWhUOHZVd1FmR1owRGxsL2dTU0wrSXdIYVdYYi96UkVDWDNBWUIxQVNQbVVteElBaWhYU3RTREhCZ0JudlkvMnpZa0grTC9pWVd3eGtSS0F5aTJXd2MvNEZGSmFkOU4zZExOSGR2L3d4MENGUmRjSGMwWDhKSk11T3VqYjZsa0U2NEpHNkhyWDZ3Kys1ay90T05RTnlUS0VLNjZzQ3NFTEYzU3N3ekpEbkJCMjhJd09QaXpqajNLdzBvZCtZNlpwOCtFa0hpTzBBTmVETEhRV0tqSUY4MEFmNHgwVEdZSUtMZ214aXBTeVAzZWhMbWdnbWZyWjduSkdxSG1RdmZKSW1FalU3OXpCdHBjVUhROWxZZnk0TU4vRXhFa3NoTG9lbU5MUWJrSWRqTExuczd1Z2dnS2VXY1RvanZnPSIsImFfcmVzcG9uc2VzIjp7IjAiOiJRREpiYXA1REJjL3ExbkFjcDJzb2FEYkhJYklSN245RmFoU0tlVUFVdWI5N0hCOTZrK2NKbU5aUWRVSlpqdVU3eEdrTW8zNWdxTjRHdmVHSVJ6cnpsa21HMHExY1d1RHBaUUE9IiwiMyI6IkJGYnh1MmxSWVRxNm5PL2RxR1FSQTJhajA0ZnNIU25kQU9vbXRTWnN0VVpEMmo3QU5lTTN1dFhuMGNIekxPZ3pxcksra01TQndTRDlLY2xxZDk5M3NCV3cwUHVoWTVoZXdvQlI4SCsvVWhFPSJ9LCJhX2Rpc2Nsb3NlZCI6eyIxIjoiQXdBS0N3QWFBQUJIMmprbFV0czVpQldTbEtMaE1qdmkiLCIyIjoiWUdCZ1lHQmdZR009In19XSwiaW5kaWNlcyI6W1t7ImNyZWQiOjAsImF0dHIiOjJ9XV0sIm5vbmNlIjoieWUvTjRKNGM1ZG5MalNCZTNvaEdSQT09IiwiY29udGV4dCI6IkFRPT0iLCJtZXNzYWdlIjoiTkw6QmVoYW5kZWxhYXJMb2dpbjp2MSBPbmRlcmdldGVrZW5kZSBnZWVmdCB0b2VzdGVtbWluZyBhYW4gRGVtbyBFSFIgb20gdWl0IHppam4vaGFhciBuYWFtIGhldCBOdXRzIG5ldHdlcmsgdGUgYmV2cmFnZW4uIERlemUgdG9lc3RlbW1pbmcgaXMgZ2VsZGlnIHZhbiBtYWFuZGFnLCAxIGp1bGkgMjAxOSAxNDozNjo0OSB0b3QgbWFhbmRhZywgMSBqdWxpIDIwMTkgMTU6MzY6NDkuIiwidGltZXN0YW1wIjp7IlRpbWUiOjE1NjE5ODQ2NDYsIlNlcnZlclVybCI6Imh0dHBzOi8vbWV0cmljcy5wcml2YWN5YnlkZXNpZ24uZm91bmRhdGlvbi9hdHVtIiwiU2lnIjp7IkFsZyI6ImVkMjU1MTkiLCJEYXRhIjoiNTl6dHhLRVViVnA3RTZTa1hjdWRrN3FlOUdKOWwrTE05NllacWxhd2x5dXdXSEhxZkg2a2ZRbjAvMHNUdnN6T3JydTlZUStLSm5SdXd1WGVXR1duQnc9PSIsIlB1YmxpY0tleSI6ImUvbk1BSkY3bndydk5aUnB1SmxqTnBSeCtDc1Q3Y2FhWHluOU9YNjgzUjg9In19fX19.zTV8pb71A8E-B3YOaY5zAJaMFlDN7fiV0bKJtAufeoA"

		result, err := validator.ValidateJwt(token, "Demo EHR")

		assert.Nil(t, result)
		assert.Error(t, err)
		assert.True(t, xerrors.Is(err, ErrInvalidContract))
		assert.Equal(t,  "could not verify jwt: invalid contract", err.Error())
	})

	t.Run("wrong issuer", func(t *testing.T) {
		validator := DefaultValidator{}
		token := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJ3cm9uZy1pc3N1ZXIiLCJudXRzX3NpZ25hdHVyZSI6eyJJcm1hQ29udHJhY3QiOnsic2lnbmF0dXJlIjpbeyJjIjoiUDB3MVZJeWxHcTJybU1mazY1b3B6S2xBc2RSRjZEYUVHYnNqZkVaWEtadz0iLCJBIjoiMDNBNVpzL0U2T3pjbE1laFZ6eGdDZlZFTjYvNUR6WllEY1Qwb0V5RG4xY2k1bzBKL2ZLV1RrRVZRbXFTcnlHbzh5U0toOEttYWhkSU5JMDljS3pMcEc2alpVNW0yRkVwNExwMzFBeGcxRDdZREJGMjBnUGcvVytRTlRVdllBcVVZMk1HMjAvWFVSZEZreWpaQmJ4WGFpTEVaOUtPRjZtT1dCa2pJZGlRbnZDWGJSMnRPVHNsWkdHVHlOSlp2WStCeG8xbk1vRWF5c2tMWWtLVFRybUhzTzRKZSszTVFKT1JkOFJLb2xBQzdHakgzSHpqaGx6dDd6endYRzZqcXBMQVVDWFdEMEZ2eEpBalFKaW05V05jTTdlNVUzZ0pLTjJTWGFOMk9tTEJ0ejZqZUdRbVpuNElsOWRXWjI5WWhBcWxrcXVCUW9jME1NdEdML3VWb1FpcGF3PT0iLCJlX3Jlc3BvbnNlIjoiRXlhZEY5a054TXpwZWF1bHN5TW12WitTdW1jejBsTm1UYUpiN0tXSlRUMFFDaUZNY2k4ZDI0SU9IWm1YRTE4WEpIdHdlbWU3bEdkTTRVSEc5cTB5Iiwidl9yZXNwb25zZSI6IkR5OUVSemQwcTBHTjMzc3YxOVR1SXZPeitZb0JTbVFCY1lFTXI3M2FZemRoNGZUNkZqdFVWRGt0UjRZN0U0RExteEhPS21KMmtIbVRCbEJIdURQdnErR3QyQlFIY3lvdHVoRzd2RXdkOGM4dVhtb3NxNVNaYjZlVDBMc3R2MlpYM2dzd0thSGVyeC9Wb2ovZndVazB3NFd6OXpEN3FpZi8rd3ZaYVA0NW9oVDhheHZqd21BajdjekxSUWtQN0ovb284ZUxJaVpHUnZZUVlvRkN5bFU1eklDR1p3aEJJaFQ4dlV3UWZHWjBEbGwvZ1NTTCtJd0hhV1hiL3pSRUNYM0FZQjFBU1BtVW14SUFpaFhTdFNESEJnQm52WS8yellrSCtML2lZV3d4a1JLQXlpMld3Yy80RkZKYWQ5TjNkTE5IZHYvd3gwQ0ZSZGNIYzBYOEpKTXVPdWpiNmxrRTY0Skc2SHJYNncrKzVrL3RPTlFOeVRLRUs2NnNDc0VMRjNTc3d6SkRuQkIyOEl3T1BpempqM0t3MG9kK1k2WnA4K0VrSGlPMEFOZURMSFFXS2pJRjgwQWY0eDBUR1lJS0xnbXhpcFN5UDNlaExtZ2dtZnJaN25KR3FIbVF2ZkpJbUVqVTc5ekJ0cGNVSFE5bFlmeTRNTi9FeEVrc2hMb2VtTkxRYmtJZGpMTG5zN3VnZ2dLZVdjVG9qdmc9IiwiYV9yZXNwb25zZXMiOnsiMCI6IlFESmJhcDVEQmMvcTFuQWNwMnNvYURiSEliSVI3bjlGYWhTS2VVQVV1Yjk3SEI5NmsrY0ptTlpRZFVKWmp1VTd4R2tNbzM1Z3FONEd2ZUdJUnpyemxrbUcwcTFjV3VEcFpRQT0iLCIzIjoiQkZieHUybFJZVHE2bk8vZHFHUVJBMmFqMDRmc0hTbmRBT29tdFNac3RVWkQyajdBTmVNM3V0WG4wY0h6TE9nenFySytrTVNCd1NEOUtjbHFkOTkzc0JXdzBQdWhZNWhld29CUjhIKy9VaEU9In0sImFfZGlzY2xvc2VkIjp7IjEiOiJBd0FLQ3dBYUFBQkgyamtsVXRzNWlCV1NsS0xoTWp2aSIsIjIiOiJZR0JnWUdCZ1lHTT0ifX1dLCJpbmRpY2VzIjpbW3siY3JlZCI6MCwiYXR0ciI6Mn1dXSwibm9uY2UiOiJ5ZS9ONEo0YzVkbkxqU0JlM29oR1JBPT0iLCJjb250ZXh0IjoiQVE9PSIsIm1lc3NhZ2UiOiJOTDpCZWhhbmRlbGFhckxvZ2luOnYxIE9uZGVyZ2V0ZWtlbmRlIGdlZWZ0IHRvZXN0ZW1taW5nIGFhbiBEZW1vIEVIUiBvbSB1aXQgemlqbi9oYWFyIG5hYW0gaGV0IE51dHMgbmV0d2VyayB0ZSBiZXZyYWdlbi4gRGV6ZSB0b2VzdGVtbWluZyBpcyBnZWxkaWcgdmFuIG1hYW5kYWcsIDEganVsaSAyMDE5IDE0OjM2OjQ5IHRvdCBtYWFuZGFnLCAxIGp1bGkgMjAxOSAxNTozNjo0OS4iLCJ0aW1lc3RhbXAiOnsiVGltZSI6MTU2MTk4NDY0NiwiU2VydmVyVXJsIjoiaHR0cHM6Ly9tZXRyaWNzLnByaXZhY3lieWRlc2lnbi5mb3VuZGF0aW9uL2F0dW0iLCJTaWciOnsiQWxnIjoiZWQyNTUxOSIsIkRhdGEiOiI1OXp0eEtFVWJWcDdFNlNrWGN1ZGs3cWU5R0o5bCtMTTk2WVpxbGF3bHl1d1dISHFmSDZrZlFuMC8wc1R2c3pPcnJ1OVlRK0tKblJ1d3VYZVdHV25Cdz09IiwiUHVibGljS2V5IjoiZS9uTUFKRjdud3J2TlpScHVKbGpOcFJ4K0NzVDdjYWFYeW45T1g2ODNSOD0ifX19fX0.wnPqCCnmrkkcYhay8iSLzfE5hBRGWJrAsrgJK3e9FW8"

		result, err := validator.ValidateJwt(token, "Demo EHR")
		assert.Nil(t, result)
		assert.Error(t, err)
		assert.True(t, xerrors.Is(err, ErrInvalidContract))
		assert.Equal(t,  "jwt does not have the nuts issuer: invalid contract", err.Error())

	})
}
