package auth

import (
	"github.com/goodsign/monday"
	"reflect"
	"regexp"
	"testing"
	"time"
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
	contract := &Contract{
		Type:               "Simple",
		Template:           "ik geef toestemming voor {{voor}} aan {{wie}}.",
		TemplateAttributes: []string{"voor", "wie"},
		Regexp:             r,
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

func TestParseTime(t *testing.T) {
	t.Run("parse Dutch time", func(t *testing.T) {
		contractTime := "Woensdag, 3 April 2019 16:36:06"
		parsedTime, err := parseTime(contractTime, "NL")
		if err != nil {
			t.Error("expected date to be parsed")
		}

		location, _ := time.LoadLocation("Europe/Amsterdam")
		expectedTime := time.Date(2019, 4, 3, 16, 36, 06, 0, location)

		if !parsedTime.Equal(expectedTime) {
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

		if !parsedTime.Equal(expectedTime) {
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

	t.Run("a valid contract returns no error", func(t *testing.T) {
		validFromStr := monday.Format(time.Now().Add(-30*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)
		validToStr := monday.Format(time.Now().Add(30*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)

		err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr, "valid_to": validToStr})
		if err != nil {
			t.Errorf("expected contract to be valid. Got %v", err)
		}
	})

	t.Run("time range checks", func(t *testing.T) {

		t.Run("a contract with invalid time range returns an error", func(t *testing.T) {
			validFromStr := monday.Format(time.Now().Add(30*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)
			validToStr := monday.Format(time.Now().Add(-30*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)

			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr, "valid_to": validToStr})
			expected := "invalid time range"
			if err.Error() != expected {
				t.Errorf("expected '%v', got '%v'", expected, err)
			}
		})

		t.Run("a contract valid in the future returns an error", func(t *testing.T) {
			validFromStr := monday.Format(time.Now().Add(30*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)
			validToStr := monday.Format(time.Now().Add(130*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)

			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr, "valid_to": validToStr})
			expected := "contract is not yet valid"
			if err.Error() != expected {
				t.Errorf("expected '%v', got '%v'", expected, err)
			}
		})

		t.Run("an expired contract returns an error", func(t *testing.T) {
			validFromStr := monday.Format(time.Now().Add(-130*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)
			validToStr := monday.Format(time.Now().Add(-30*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)

			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr, "valid_to": validToStr})
			expected := "contract is expired"
			if err.Error() != expected {
				t.Errorf("expected '%v', got '%v'", expected, err)
			}
		})
	})

	t.Run("missing parameters", func(t *testing.T) {

		t.Run("no language return an error", func(t *testing.T) {
			validFromStr := monday.Format(time.Now().Add(-30*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)
			validToStr := monday.Format(time.Now().Add(30*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)

			err := contract.ValidateTimeFrame(map[string]string{"valid_from": validFromStr, "valid_to": validToStr})
			if err.Error() != "could not determine contract language" {
				t.Error("expected an error")
			}
		})

		t.Run("no valid_from returns an error", func(t *testing.T) {
			validToStr := monday.Format(time.Now().Add(130*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)
			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_to": validToStr})
			if err.Error() != "valid_from missing in params" {
				t.Error("expected an error")
			}
		})

		t.Run("no valid_to returns an error", func(t *testing.T) {
			validFromStr := monday.Format(time.Now().Add(30*time.Minute), TIME_LAYOUT, monday.LocaleNlNL)
			err := contract.ValidateTimeFrame(map[string]string{"language": "NL", "valid_from": validFromStr})
			if err.Error() != "valid_to missing in params" {
				t.Errorf("expected an error, got: %v", err)
			}
		})
	})
}
