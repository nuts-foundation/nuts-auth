package auth

import (
	"fmt"
	"github.com/cbroglie/mustache"
	"github.com/go-errors/errors"
	"github.com/goodsign/monday"
	"github.com/sirupsen/logrus"
	"regexp"
	"time"
)

const TIME_LAYOUT = "Monday, 2 January 2006 15:04:05"

type Contract struct {
	Type               string   `json:"type"`
	Version            string   `json:"version"`
	Language           string   `json:"language"`
	SignerAttributes   []string `json:"signer_attributes"`
	Template           string   `json:"template"`
	TemplateAttributes []string `json:"template_attributes"`
	Regexp             *regexp.Regexp
}

type ContractSigningRequest struct {
	Type               string `json:"type"`
	Version            string `json:"version"`
	Language           string `json:"language"`
	TemplateAttributes map[string]string
}

func ContractByType(contractType string, language string) *Contract {

	switch contractType {
	case "PractitionerLogin", "BehandelaarLogin":
		r, _ := regexp.Compile(`NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan (.+) om uit zijn/haar naam het nuts netwerk te bevragen. Deze toestemming is geldig van (.+) tot (.+).`)
		return &Contract{
			Type:               contractType,
			Version:            "v1",
			Language:           "NL",
			SignerAttributes:   []string{"irma-demo.nuts.agb.agbcode"},
			Template:           `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan {{acting_party}} om uit zijn/haar naam het nuts netwerk te bevragen. Deze toestemming is geldig van {{valid_from}} tot {{valid_to}}.`,
			TemplateAttributes: []string{"acting_party", "valid_from", "valid_to"},
			Regexp:             r,
		}
	}

	logrus.Warnf("Contract with type '%v' and language '%v' not found", contractType, language)

	return nil
}

func (c Contract) RenderTemplate(vars map[string]string) (string, error) {
	return mustache.Render(c.Template, vars)
}

func (c Contract) ExtractParams(text string) (map[string]string, error) {
	matchResult := c.Regexp.FindSubmatch([]byte(text))
	if len(matchResult) < 1 {
		return nil, errors.New("Could not match the text")
	}
	matches := matchResult[1:]

	if len(matches) != len(c.TemplateAttributes) {
		return nil, errors.New(fmt.Sprintf("amount of template attributes does not match the amount of params: found: %d, expected %d", len(matches), len(c.TemplateAttributes)))
	}

	result := make(map[string]string, len(matches))

	for i, m := range matches {
		result[c.TemplateAttributes[i]] = string(m)
	}

	return result, nil
}

func parseTime(timeStr, language string) (*time.Time, error) {
	amsterdamLocation, _ := time.LoadLocation("Europe/Amsterdam")
	parsedTime, err := monday.ParseInLocation(TIME_LAYOUT, timeStr, amsterdamLocation, monday.LocaleNlNL)
	if err != nil {
		logrus.WithError(err).Errorf("error parsing contract time %v", timeStr)
		return nil, err
	}
	return &parsedTime, nil
}

func (c Contract) ValidateTimeFrame(params map[string]string) error {
	var (
		lang                     string
		err                      error
		ok                       bool
		validFrom, validTo       *time.Time
		validFromStr, validToStr string
	)

	if lang, ok = params["language"]; !ok {
		return errors.New("could not determine contract language")
	}

	if validFromStr, ok = params["valid_from"]; !ok {
		return errors.New("valid_from missing in params")
	}

	validFrom, err = parseTime(validFromStr, lang)
	if err != nil {
		return err
	}

	if validToStr, ok = params["valid_to"]; !ok {
		return errors.New("valid_to missing in params")
	}

	validTo, err = parseTime(validToStr, lang)
	if err != nil {
		return err
	}

	// All parsed, check time range
	if validFrom.After(*validTo) {
		return errors.New("invalid time range")
	}

	amsterdamLocation, _ := time.LoadLocation("Europe/Amsterdam")

	if time.Now().In(amsterdamLocation).Before(*validFrom) {
		return errors.New("contract is not yet valid")

	}
	if time.Now().In(amsterdamLocation).After(*validTo) {
		return errors.New("contract is expired")
	}

	return nil
}
