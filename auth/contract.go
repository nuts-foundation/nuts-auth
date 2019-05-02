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

const TimeLayout = "Monday, 2 January 2006 15:04:05"

type Contract struct {
	Type               string   `json:"type"`
	Version            string   `json:"version"`
	Language           string   `json:"language"`
	SignerAttributes   []string `json:"signer_attributes"`
	Template           string   `json:"template"`
	TemplateAttributes []string `json:"template_attributes"`
	Regexp             string   `json:"-"`
}

type ContractSigningRequest struct {
	Type               string    `json:"type"`
	Version            string    `json:"version"`
	Language           string    `json:"language"`
	ValidFrom          time.Time `json:"valid_from"`
	ValidTo            time.Time `json:"valid_to"`
	TemplateAttributes map[string]string
}

type Language string
type Type string
type Version string

// EN:PractitionerLogin:v1 Contract
var contracts = map[Language]map[Type]map[Version]*Contract{
	"NL": {"BehandelaarLogin": {"v1": &Contract{
		Type:               "BehandelaarLogin",
		Version:            "v1",
		Language:           "NL",
		SignerAttributes:   []string{"irma-demo.nuts.agb.agbcode"},
		Template:           `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan {{acting_party}} om uit zijn/haar naam het Nuts netwerk te bevragen. Deze toestemming is geldig van {{valid_from}} tot {{valid_to}}.`,
		TemplateAttributes: []string{"acting_party", "valid_from", "valid_to"},
		Regexp:             `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan (.+) om uit zijn/haar naam het Nuts netwerk te bevragen. Deze toestemming is geldig van (.+) tot (.+).`,
	}}},
	"EN": {"PractitionerLogin": {"v1": &Contract{
		Type:               "PractitionerLogin",
		Version:            "v1",
		Language:           "EN",
		SignerAttributes:   []string{"irma-demo.nuts.agb.agbcode"},
		Template:           `EN:PractitionerLogin:v1 Undersigned gives permission to {{acting_party}} to make request on its behalf to the Nuts network. This permission is valid from {{valid_from}} until {{valid_to}}.`,
		TemplateAttributes: []string{"acting_party", "valid_from", "valid_to"},
		Regexp:             `EN:PractitionerLogin:v1 Undersigned gives permission to (.+) to make request on its behalf to the Nuts network. This permission is valid from (.+) until (.+).`,
	}}},
}

func ContractFromMessageContents(contents string) *Contract {
	r, _ := regexp.Compile(`^(.{2}):(.+):(v\d+)`)

	matchResult := r.FindSubmatch([]byte(contents))
	if len(matchResult) != 4 {
		logrus.Error("Could not extract type, language and version form contract text")
		return nil
	}

	language := string(matchResult[1])
	contractType := string(matchResult[2])
	version := string(matchResult[3])

	return ContractByType(contractType, language, version)

}

func ContractByType(contractType string, language, version string) *Contract {
	if version == "" {
		version = "v1"
	}
	contract, ok := contracts[Language(language)][Type(contractType)][Version(version)]
	if ok {
		return contract
	}
	logrus.Warnf("Contract with type '%s' language '%s' and version %s not found", contractType, language, version)
	return nil
}

func (c Contract) timeLocation() *time.Location {
	loc, _ := time.LoadLocation("Europe/Amsterdam")
	return loc
}

func (c Contract) RenderTemplate(vars map[string]string, validFromOffset, validToOffset time.Duration) (string, error) {
	vars["valid_from"] = monday.Format(time.Now().Add(validFromOffset).In(c.timeLocation()), TimeLayout, monday.LocaleNlNL)
	vars["valid_to"] = monday.Format(time.Now().Add(validToOffset).In(c.timeLocation()), TimeLayout, monday.LocaleNlNL)

	return mustache.Render(c.Template, vars)
}

func (c Contract) ExtractParams(text string) (map[string]string, error) {
	r, _ := regexp.Compile(c.Regexp)
	matchResult := r.FindSubmatch([]byte(text))
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
	parsedTime, err := monday.ParseInLocation(TimeLayout, timeStr, amsterdamLocation, monday.LocaleNlNL)
	if err != nil {
		logrus.WithError(err).Errorf("error parsing contract time %v", timeStr)
		return nil, err
	}
	return &parsedTime, nil
}

func (c Contract) ValidateTimeFrame(params map[string]string) (bool, error) {
	var (
		err                      error
		ok                       bool
		validFrom, validTo       *time.Time
		validFromStr, validToStr string
	)

	if validFromStr, ok = params["valid_from"]; !ok {
		return false, errors.New("valid_from missing in params")
	}

	validFrom, err = parseTime(validFromStr, c.Language)
	if err != nil {
		return false, err
	}

	if validToStr, ok = params["valid_to"]; !ok {
		return false, errors.New("valid_to missing in params")
	}

	validTo, err = parseTime(validToStr, c.Language)
	if err != nil {
		return false, err
	}

	// All parsed, check time range
	if validFrom.After(*validTo) {
		return false, errors.New("invalid time range")
	}

	amsterdamLocation, _ := time.LoadLocation("Europe/Amsterdam")
	now := time.Now()
	logrus.Infof("checking timeframe: now %v, validFrom: %v, validTo: %v", now, *validFrom, *validTo)

	if now.In(amsterdamLocation).Before(*validFrom) {
		logrus.Info("contract is not yet valid")
		return false, nil

	}
	if now.In(amsterdamLocation).After(*validTo) {
		logrus.Info("contract is expired")
		return false, nil
	}

	return true, nil
}
