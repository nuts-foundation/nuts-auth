package pkg

import (
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/cbroglie/mustache"
	"github.com/goodsign/monday"
	"github.com/sirupsen/logrus"
)

const timeLayout = "Monday, 2 January 2006 15:04:05"

// Contract stores the properties of a contract
type Contract struct {
	Type                 ContractType `json:"type"`
	Version              Version      `json:"version"`
	Language             Language     `json:"language"`
	SignerAttributes     []string     `json:"signer_attributes"`
	SignerDemoAttributes []string     `json:"-"`
	Template             string       `json:"template"`
	TemplateAttributes   []string     `json:"template_attributes"`
	Regexp               string       `json:"-"`
}

// Language of the contract in all caps. example: "NL"
type Language string

// ContractType contains type of the contract to sign. Example: "BehandelaarLogin"
type ContractType string

// Version of the contract. example: "v1"
type Version string

// NowFunc is used to store a function that returns the current time. This can be changed when you want to mock the current time.
var NowFunc = time.Now

// ErrContractNotFound is used when a certain combination of type, language and version cannot resolve to a contract
var ErrContractNotFound = errors.New("contract not found")

// ErrInvalidContractText is used when contract texts cannot be parsed or contain invalid values
var ErrInvalidContractText = errors.New("invalid contract text")

// StandardSignerAttributes defines the standard list of attributes used for a contract.
// If SignerAttribute name starts with a dot '.', it uses the configured scheme manager
var StandardSignerAttributes = []string{
	".gemeente.personalData.fullname",
	".gemeente.personalData.firstnames",
	".gemeente.personalData.prefix",
	".gemeente.personalData.familyname",
	"pbdf.pbdf.email.email",
}

// EN:PractitionerLogin:v1 Contract
var contracts = map[Language]map[ContractType]map[Version]*Contract{
	"NL": {"BehandelaarLogin": {"v1": &Contract{
		Type:               "BehandelaarLogin",
		Version:            "v1",
		Language:           "NL",
		SignerAttributes:   StandardSignerAttributes,
		Template:           `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan {{acting_party}} om namens {{legal_entity}} en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van {{valid_from}} tot {{valid_to}}.`,
		TemplateAttributes: []string{"acting_party", "legal_entity", "valid_from", "valid_to"},
		Regexp:             `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan (.+) om namens (.+) en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van (.+) tot (.+).`,
	}}},
	"EN": {"PractitionerLogin": {"v1": &Contract{
		Type:               "PractitionerLogin",
		Version:            "v1",
		Language:           "EN",
		SignerAttributes:   StandardSignerAttributes,
		Template:           `EN:PractitionerLogin:v1 Undersigned gives permission to {{acting_party}} to make request to the Nuts network on behalf of {{legal_entity}} and itself. This permission is valid from {{valid_from}} until {{valid_to}}.`,
		TemplateAttributes: []string{"acting_party", "legal_entity", "valid_from", "valid_to"},
		Regexp:             `EN:PractitionerLogin:v1 Undersigned gives permission to (.+) to make request to the Nuts network on behalf of (.+) and itself. This permission is valid from (.+) until (.+).`,
	}}},
}

// ContractFromMessageContents finds the contract for a certain message.
// Every message should begin with a special sequence like "NL:ContractName:version".
func ContractFromMessageContents(contents string) (*Contract, error) {
	r, _ := regexp.Compile(`^(.{2}):(.+):(v\d+)`)

	matchResult := r.FindSubmatch([]byte(contents))
	if len(matchResult) != 4 {
		return nil, fmt.Errorf("%w: could not extract contract version, language and type", ErrInvalidContractText)
	}

	language := Language(matchResult[1])
	contractType := ContractType(matchResult[2])
	version := Version(matchResult[3])

	return ContractByType(contractType, language, version)

}

// ContractByType returns the contract for a certain type, language and version. If version is omitted "v1" is used
// If no contract is found, the error vaule of ErrContractNotFound is returned.
func ContractByType(contractType ContractType, language Language, version Version) (*Contract, error) {
	if version == "" {
		version = "v1"
	}
	if contract, ok := contracts[language][contractType][version]; ok {
		return contract, nil
	}

	return nil, fmt.Errorf("type %s, lang: %s, version: %s: %w", contractType, language, version, ErrContractNotFound)
}

func (c Contract) timeLocation() *time.Location {
	loc, _ := time.LoadLocation("Europe/Amsterdam")
	return loc
}

func (c Contract) renderTemplate(vars map[string]string, validFromOffset, validToOffset time.Duration) (string, error) {
	vars["valid_from"] = monday.Format(time.Now().Add(validFromOffset).In(c.timeLocation()), timeLayout, monday.LocaleNlNL)
	vars["valid_to"] = monday.Format(time.Now().Add(validToOffset).In(c.timeLocation()), timeLayout, monday.LocaleNlNL)

	return mustache.Render(c.Template, vars)
}

func (c Contract) extractParams(text string) (map[string]string, error) {
	r, _ := regexp.Compile(c.Regexp)
	matchResult := r.FindSubmatch([]byte(text))
	if len(matchResult) < 1 {
		return nil, fmt.Errorf("%w: could not match the contract template regex", ErrInvalidContractText)
	}
	matches := matchResult[1:]

	if len(matches) != len(c.TemplateAttributes) {
		return nil, fmt.Errorf("%w: amount of template attributes does not match the amount of params: found: %d, expected %d", ErrInvalidContractText, len(matches), len(c.TemplateAttributes))
	}

	result := make(map[string]string, len(matches))

	for i, m := range matches {
		result[c.TemplateAttributes[i]] = string(m)
	}

	return result, nil
}

func parseTime(timeStr string, _ Language) (*time.Time, error) {
	amsterdamLocation, _ := time.LoadLocation("Europe/Amsterdam")
	parsedTime, err := monday.ParseInLocation(timeLayout, timeStr, amsterdamLocation, monday.LocaleNlNL)
	if err != nil {
		return nil, fmt.Errorf("invalid time string [%v]: %w", timeStr, err)
	}
	return &parsedTime, nil
}

func (c Contract) validateTimeFrame(params map[string]string) (bool, error) {
	var (
		err                      error
		ok                       bool
		validFrom, validTo       *time.Time
		validFromStr, validToStr string
	)

	if validFromStr, ok = params["valid_from"]; !ok {
		return false, fmt.Errorf("%w: value for [valid_from] is missing", ErrInvalidContractText)
	}

	validFrom, err = parseTime(validFromStr, c.Language)
	if err != nil {
		return false, fmt.Errorf("%w: unable to parse [valid_from]: %s", ErrInvalidContractText, err)

	}

	if validToStr, ok = params["valid_to"]; !ok {
		return false, fmt.Errorf("%w: value for [valid_to] is missing", ErrInvalidContractText)
	}

	validTo, err = parseTime(validToStr, c.Language)
	if err != nil {
		return false, fmt.Errorf("%w: unable to parse [valid_to]: %s", ErrInvalidContractText, err)
	}

	// All parsed, check time range
	if validFrom.After(*validTo) {
		return false, fmt.Errorf("%w: [valid_from] must be after [valid_to]", ErrInvalidContractText)
	}

	amsterdamLocation, _ := time.LoadLocation("Europe/Amsterdam")
	now := NowFunc()
	logrus.Debugf("checking timeframe: now %v, validFrom: %v, validTo: %v", now, *validFrom, *validTo)

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
