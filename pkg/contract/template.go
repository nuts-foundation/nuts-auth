package contract

import (
	"errors"
	"time"

	"github.com/cbroglie/mustache"
	"github.com/goodsign/monday"
)

const timeLayout = "Monday, 2 January 2006 15:04:05"
const ValidFromAttr = "valid_from"
const ValidToAttr = "valid_to"
const ActingPartyAttr = "acting_party"
const LegalEntityAttr = "legal_entity"

// Template stores al properties of a contract template which can result in a signed contract
type Template struct {
	Type                 Type     `json:"type"`
	Version              Version  `json:"version"`
	Language             Language `json:"language"`
	SignerAttributes     []string `json:"signer_attributes"`
	SignerDemoAttributes []string `json:"-"`
	Template             string   `json:"Template"`
	TemplateAttributes   []string `json:"template_attributes"`
	Regexp               string   `json:"-"`
}

// Language of the contract in all caps. example: "NL"
type Language string

// Type contains type of the contract to sign. Example: "BehandelaarLogin"
type Type string

// Version of the contract. example: "v1"
type Version string

// NowFunc is used to store a function that returns the current time. This can be changed when you want to mock the current time.
var NowFunc = time.Now

// StandardSignerAttributes defines the standard list of attributes used for a contract.
// If SignerAttribute name starts with a dot '.', it uses the configured scheme manager
var StandardSignerAttributes = []string{
	".gemeente.personalData.firstnames",
	"pbdf.pbdf.email.email",
}

func (c Template) timeLocation() *time.Location {
	loc, _ := time.LoadLocation("Europe/Amsterdam")
	return loc
}

func (c Template) Render(vars map[string]string, validFromOffset, validToOffset time.Duration) (*Contract, error) {
	vars[ValidFromAttr] = monday.Format(time.Now().Add(validFromOffset).In(c.timeLocation()), timeLayout, monday.LocaleNlNL)
	vars[ValidToAttr] = monday.Format(time.Now().Add(validToOffset).In(c.timeLocation()), timeLayout, monday.LocaleNlNL)

	rawContractText, err := mustache.Render(c.Template, vars)
	if err != nil {
		return nil, err
	}

	contract := &Contract{
		RawContractText: rawContractText,
		Template:        &c,
	}
	if err := contract.extractParams(); err != nil {
		return nil, err
	}

	return contract, nil
}

// ErrUnknownContractFormat is returned when the contract format is unknown
var ErrUnknownContractFormat = errors.New("unknown contract format")

// ErrInvalidContractFormat indicates tha a contract format is unknown.
var ErrInvalidContractFormat = errors.New("unknown contract type")

// ErrContractNotFound is used when a certain combination of type, language and version cannot resolve to a contract
var ErrContractNotFound = errors.New("contract not found")

// ErrInvalidContractText is used when contract texts cannot be parsed or contain invalid values
var ErrInvalidContractText = errors.New("invalid contract text")
