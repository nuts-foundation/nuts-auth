package auth

import (
	"github.com/cbroglie/mustache"
	"github.com/go-errors/errors"
	"github.com/sirupsen/logrus"
	"regexp"
)

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

func (c Contract) ExtractParams(text string) ([]string, error) {
	matchResult := c.Regexp.FindSubmatch([]byte(text))
	if len(matchResult) < 1 {
		return nil, errors.New("Could not match the text")
	}
	matches := matchResult[1:]

	result := make([]string, len(matches))

	for i, m := range matches {
		result[i] = string(m)
	}

	return result, nil
}
