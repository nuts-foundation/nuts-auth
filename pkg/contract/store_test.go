package contract

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTemplateStore_FindFromRawContractText(t *testing.T) {
	t.Run("a correct triple returns the contract", func(t *testing.T) {
		expected := StandardContractTemplates[Language("NL")][Type("BehandelaarLogin")][Version("v1")]
		rawContractText := "NL:BehandelaarLogin:v1"
		got, err := StandardContractTemplates.FindFromRawContractText(rawContractText)
		assert.NoError(t, err)
		if got != expected {
			t.Errorf("Expected different contract. Expected: %v, got: %v", expected, got)
		}
	})

	t.Run("an unknown triple returns a nil", func(t *testing.T) {
		rawContractText := "DE:BehandelaarLogin:v1"

		got, err := StandardContractTemplates.FindFromRawContractText(rawContractText)
		assert.EqualError(t, err, "type BehandelaarLogin, lang: DE, version: v1: contract not found")
		assert.Nil(t, got)
	})

	t.Run("a valid triple other than at the start of the contents returns a nil", func(t *testing.T) {
		rawContractText := "some other text NL:BehandelaarLogin:v1"

		got, err := StandardContractTemplates.FindFromRawContractText(rawContractText)
		assert.EqualError(t, err, "invalid contract text: could not extract contract version, language and type")
		assert.Nil(t, got)
	})

}

func TestTemplateStore_Find(t *testing.T) {
	t.Run("It finds a known Dutch Template", func(t *testing.T) {
		want := Type("BehandelaarLogin")
		if got, _ := StandardContractTemplates.Find(want, "NL", "v1"); got.Type != want {
			t.Errorf("NewByType() = %v, want %v", got, want)
		}
	})

	t.Run("It uses the latest version if no version is provided", func(t *testing.T) {
		want := Version("v1")
		if got, _ := StandardContractTemplates.Find("BehandelaarLogin", "NL", ""); got.Version != want {
			t.Errorf("Wrong language %v, want %v", got, want)
		}
	})

	t.Run("It finds a known English Template", func(t *testing.T) {
		want := Type("PractitionerLogin")
		if got, _ := StandardContractTemplates.Find(want, "EN", "v1"); got.Type != want {
			t.Errorf("NewByType() = %v, want %v", got, want)
		}
	})

	t.Run("An unknown contract should return a nil", func(t *testing.T) {
		want := Type("UnknownContract")
		if got, _ := StandardContractTemplates.Find(want, "NL", "v1"); got != nil {
			t.Errorf("NewByType() = %v, want %v", got, nil)
		}
	})
}
