package auth

import (
	"testing"
)

func TestContractByType(t *testing.T) {
	t.Run("find a known template", func(t *testing.T) {
		want := "BehandelaarLogin"
		if got := ContractByType(want, "NL"); got.Type != want {
			t.Errorf("ContractByType() = %v, want %v", got, want)
		}
	})

	t.Run("An unknown contract should return a nil", func(t *testing.T) {
		want := "UnknownContract"
		if got := ContractByType(want, "NL"); got != nil {
			t.Errorf("ContractByType() = %v, want %v", got, nil)
		}
	})
}

func TestContract_RenderTemplate(t *testing.T) {
	contract := &Contract{Type: "Simple", Template: "ga je akkoord met {{wat}}?"}
	result, err := contract.RenderTemplate(map[string]string{"wat": "alles"})
	if err != nil {
		t.Error(err)
	}

	expected := "ga je akkoord met alles?"
	if result != expected {
		t.Errorf("Error while rendering the template: got '%v', expected '%v'", result, expected)
	}
}
