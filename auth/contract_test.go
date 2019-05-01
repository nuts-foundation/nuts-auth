package auth

import (
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/goodsign/monday"
)

func TestContractByType(t *testing.T) {
	t.Run("It finds a known Dutch template", func(t *testing.T) {
		want := "BehandelaarLogin"
		if got := ContractByType(want, "NL", "v1"); got.Type != want {
			t.Errorf("ContractByType() = %v, want %v", got, want)
		}
	})

	t.Run("It uses the latest version if no version is provided", func(t *testing.T) {
		want := "v1"
		if got := ContractByType("BehandelaarLogin", "NL", ""); got.Version != want {
			t.Errorf("Wrong language %v, want %v", got, want)
		}
	})

	t.Run("It finds a known English template", func(t *testing.T) {
		want := "PractitionerLogin"
		if got := ContractByType(want, "EN", "v1"); got.Type != want {
			t.Errorf("ContractByType() = %v, want %v", got, want)
		}
	})

	t.Run("An unknown contract should return a nil", func(t *testing.T) {
		want := "UnknownContract"
		if got := ContractByType(want, "NL", "v1"); got != nil {
			t.Errorf("ContractByType() = %v, want %v", got, nil)
		}
	})
}

func TestContractByContents(t *testing.T) {
	t.Run("a correct triple returns the contract", func(t *testing.T) {
		expected := contracts[Language("NL")][Type("BehandelaarLogin")][Version("v1")]
		got := ContractByContents("NL:BehandelaarLogin:v1")
		if got != expected {
			t.Errorf("Expected different contract. Expected: %v, got: %v", expected, got)
		}
	})

	t.Run("an unknown triple returns a nil", func(t *testing.T) {
		var expected *Contract = nil

		got := ContractByContents("DE:BehandelaarLogin:v1")
		if got != expected {
			t.Errorf("Expected different contract. Expected: %v, got: %v", expected, got)
		}
	})

	t.Run("the triple does not work if it is not at the tart of the contract", func(t *testing.T) {
		var expected *Contract = nil

		got := ContractByContents("some other text NL:BehandelaarLogin:v1")
		if got != expected {
			t.Errorf("Expected different contract. Expected: %v, got: %v", expected, got)
		}
	})

}

func TestContract_RenderTemplate(t *testing.T) {
	contract := &Contract{Type: "Simple", Template: "ga je akkoord met {{wat}} van {{valid_from}} tot {{valid_to}}?"}
	result, err := contract.RenderTemplate(map[string]string{"wat": "alles"}, 0, 60*time.Minute)
	if err != nil {
		t.Error(err)
	}
	amsterdamLocation, _ := time.LoadLocation("Europe/Amsterdam")

	from := monday.Format(time.Now().In(amsterdamLocation).Add(0), TimeLayout, monday.LocaleNlNL)
	to := monday.Format(time.Now().In(amsterdamLocation).Add(60*time.Minute), TimeLayout, monday.LocaleNlNL)

	expected := fmt.Sprintf("ga je akkoord met alles van %s tot %s?", from, to)
	if result != expected {
		t.Errorf("Error while rendering the template: got '%v', expected '%v'", result, expected)
	}
}

func TestContract_ExtractParams(t *testing.T) {
	contract := &Contract{
		Type:               "Simple",
		Template:           "ik geef toestemming voor {{voor}} aan {{wie}}.",
		TemplateAttributes: []string{"voor", "wie"},
		Regexp:             `^ik geef toestemming voor (.*) aan (.*)\.$`,
	}

	t.Run("a good text returns the params", func(t *testing.T) {
		contractText := "ik geef toestemming voor orgaandonatie aan Henk."

		expectedParams := map[string]string{"voor": "orgaandonatie", "wie": "Henk"}

		params, err := contract.ExtractParams(contractText)
		if err != nil {
			t.Error(err)
		}

		if !reflect.DeepEqual(expectedParams, params) {
			t.Errorf("expected different params, expected %v, got %v", expectedParams, params)
		}
	})

	t.Run("an invalid text returns an error", func(t *testing.T) {
		contract := &Contract{Type: "Simple", Template: "ik geef toestemming voor {{voor}} aan {{wie}}.", Regexp: `^ik geef toestemming voor (.*) aan (.*)\.$`}

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

func TestParseTime(t *testing.T) {
	t.Run("parse Dutch time", func(t *testing.T) {
		contractTime := "Woensdag, 3 April 2019 16:36:06"
		parsedTime, err := parseTime(contractTime, "NL")
		if err != nil {
			t.Error("expected date to be parsed")
		}

		location, _ := time.LoadLocation("Europe/Amsterdam")
		expectedTime := time.Date(2019, 4, 3, 16, 36, 06, 0, location)

		if parsedTime == nil || !parsedTime.Equal(expectedTime) {
			t.Errorf("expected dutch time to be parsed. Got %v, expected %v", parsedTime, expectedTime)
		}
	})

	t.Run("parse English time", func(t *testing.T) {
		contractTime := "Wednesday, 3 April 2019 16:36:06"
		parsedTime, err := parseTime(contractTime, "EN")
		if err != nil {
			t.Error("expected date to be parsed")
		}

		location, _ := time.LoadLocation("Europe/Amsterdam")
		expectedTime := time.Date(2019, 4, 3, 16, 36, 06, 0, location)

		if parsedTime == nil || !parsedTime.Equal(expectedTime) {
			t.Errorf("expected English time to be parsed. Got %v, expected %v", parsedTime, expectedTime)
		}
	})

	t.Run("parse rubbish", func(t *testing.T) {
		contractTime := "Today is gonna be the day"
		parsedTime, err := parseTime(contractTime, "EN")
		if err == nil {
			t.Error("expected an error to occur")
		}

		if parsedTime != nil {
			t.Errorf("expected parsedTime to be nil. got %v", parsedTime)
		}
	})

	t.Run("parse date with wrong day", func(t *testing.T) {
		t.Skip("This is not supported by the 'monday' package. Should we build it ourselves?")
		contractTime := "Dinsdag, 3 April 2019 16:36:06"
		parsedTime, err := parseTime(contractTime, "NL")
		if err == nil {
			t.Error("expected an error to occur")
		}

		if parsedTime != nil {
			t.Errorf("expected parsedTime to be nil. got %v", parsedTime)
		}
	})
}

func TestContract_ValidateTimeFrame(t *testing.T) {
	contract := &Contract{
		Type:               "Simple",
		Template:           "ik geef toestemming van {{valid_from}} tot {{valid_to}}.",
		TemplateAttributes: []string{"valid_from", "valid_to"},
	}

	timeInAmsterdam := func() time.Time {
		amsterdamLocation, _ := time.LoadLocation("Europe/Amsterdam")
		return time.Now().In(amsterdamLocation)
	}

	t.Run("a valid contract returns no error", func(t *testing.T) {
		validFromStr := monday.Format(timeInAmsterdam().Add(-30*time.Minute), TimeLayout, monday.LocaleNlNL)
		validToStr := monday.Format(timeInAmsterdam().Add(30*time.Minute), TimeLayout, monday.LocaleNlNL)

		err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr, "valid_to": validToStr})
		if err != nil {
			t.Errorf("expected contract to be valid. Got %v", err)
		}
	})

	t.Run("time range checks", func(t *testing.T) {

		t.Run("a contract with invalid time range returns an error", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(30*time.Minute), TimeLayout, monday.LocaleNlNL)
			validToStr := monday.Format(timeInAmsterdam().Add(-30*time.Minute), TimeLayout, monday.LocaleNlNL)

			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr, "valid_to": validToStr})
			expected := "invalid time range"
			if err == nil || err.Error() != expected {
				t.Errorf("expected '%v', got '%v'", expected, err)
			}
		})

		t.Run("a contract valid in the future returns an error", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(30*time.Minute), TimeLayout, monday.LocaleNlNL)
			validToStr := monday.Format(timeInAmsterdam().Add(130*time.Minute), TimeLayout, monday.LocaleNlNL)

			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr, "valid_to": validToStr})
			expected := "contract is not yet valid"
			if err == nil || err.Error() != expected {
				t.Errorf("expected '%v', got '%v'", expected, err)
			}
		})

		t.Run("an expired contract returns an error", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(-130*time.Minute), TimeLayout, monday.LocaleNlNL)
			validToStr := monday.Format(timeInAmsterdam().Add(-30*time.Minute), TimeLayout, monday.LocaleNlNL)

			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr, "valid_to": validToStr})
			expected := "contract is expired"
			if err == nil || err.Error() != expected {
				t.Errorf("expected '%v', got '%v'", expected, err)
			}
		})
	})

	t.Run("missing parameters", func(t *testing.T) {

		t.Run("no language return an error", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(-30*time.Minute), TimeLayout, monday.LocaleNlNL)
			validToStr := monday.Format(timeInAmsterdam().Add(30*time.Minute), TimeLayout, monday.LocaleNlNL)

			err := contract.ValidateTimeFrame(map[string]string{"valid_from": validFromStr, "valid_to": validToStr})
			expected := "could not determine contract language"
			if err == nil || err.Error() != expected {
				t.Error("expected an error")
			}
		})

		t.Run("no valid_from returns an error", func(t *testing.T) {
			validToStr := monday.Format(timeInAmsterdam().Add(130*time.Minute), TimeLayout, monday.LocaleNlNL)
			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_to": validToStr})
			expected := "valid_from missing in params"
			if err == nil || err.Error() != expected {
				t.Error("expected an error")
			}
		})

		t.Run("no valid_to returns an error", func(t *testing.T) {
			validFromStr := monday.Format(timeInAmsterdam().Add(30*time.Minute), TimeLayout, monday.LocaleNlNL)
			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr})
			if err == nil || err.Error() != "valid_to missing in params" {
				t.Errorf("expected an error, got: %v", err)
			}
		})
	})
}
