package auth

import (
	"encoding/base64"
	"github.com/nuts-foundation/nuts-proxy/testdata"
	"reflect"
	"testing"
)

func TestValidateContract(t *testing.T) {
	type args struct {
		contract      string
		format        ContractFormat
		actingPartyCN string
	}
	tests := []struct {
		name    string
		args    args
		want    *ValidationResponse
		wantErr bool
	}{
		{
			"it should validate",
			args{
				base64.StdEncoding.EncodeToString([]byte(testdata.ValidIrmaContract)),
				Irma,
				"Helder",
			},
			&ValidationResponse{
				Valid,
				Irma,
				map[string]string{"irma-demo.nuts.agb.agbcode": "00000001"},
			},
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DefaultValidator{}.ValidateContract(tt.args.contract, tt.args.format, tt.args.actingPartyCN)
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
