package auth

import (
	"reflect"
	"regexp"
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

func TestContract_ExtractParams(t *testing.T) {
	r, _ := regexp.Compile(`^ik geef toestemming voor (.*) aan (.*)\.$`)
	contract := &Contract{Type: "Simple", Template: "ik geef toestemming voor {{voor}} aan {{wie}}.", Regexp: r}

	t.Run("a good text returns the params", func(t *testing.T) {
		contractText := "ik geef toestemming voor orgaandonatie aan Henk."

		expectedParams := []string{"orgaandonatie", "Henk"}

		params, err := contract.ExtractParams(contractText)
		if err != nil {
			t.Error(err)
		}

		if !reflect.DeepEqual(expectedParams, params) {
			t.Errorf("expected different params, expected %v, got %v", expectedParams, params)
		}
	})

	t.Run("an invalid text returns an error", func(t *testing.T) {
		r, _ := regexp.Compile(`^ik geef toestemming voor (.*) aan (.*)\.$`)
		contract := &Contract{Type: "Simple", Template: "ik geef toestemming voor {{voor}} aan {{wie}}.", Regexp: r}

		contractText := "ik ga niet akkoord."

		params, err := contract.ExtractParams(contractText)
		if err == nil {
			t.Error("expected error on invalid contract text")
		}

		if len(params) != 0 {
			t.Errorf("expected empty params, got %v", params)
		}
	})
}
