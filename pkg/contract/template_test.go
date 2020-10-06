package contract

import (
	"fmt"
	"testing"
	"time"

	"github.com/goodsign/monday"
)

func TestContract_RenderTemplate(t *testing.T) {
	template := &Template{Type: "Simple", Template: "ga je akkoord met {{wat}} van {{valid_from}} tot {{valid_to}}?"}
	result, err := template.Render(map[string]string{"wat": "alles"}, 0, 60*time.Minute)
	if err != nil {
		t.Error(err)
	}
	amsterdamLocation, _ := time.LoadLocation("Europe/Amsterdam")

	from := monday.Format(time.Now().In(amsterdamLocation).Add(0), timeLayout, monday.LocaleNlNL)
	to := monday.Format(time.Now().In(amsterdamLocation).Add(60*time.Minute), timeLayout, monday.LocaleNlNL)

	expected := fmt.Sprintf("ga je akkoord met alles van %s tot %s?", from, to)
	if result.RawContractText != expected {
		t.Errorf("Error while rendering the Template: got '%v', expected '%v'", result, expected)
	}
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
