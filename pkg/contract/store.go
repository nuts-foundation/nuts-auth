/*
 * Nuts auth
 * Copyright (C) 2020. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package contract

import (
	"fmt"
	"regexp"
)

// StandardContractTemplates contains a the official contract templates as specified in the Nuts specification
// EN:PractitionerLogin:v1 Template
var StandardContractTemplates = TemplateStore{
	"NL": {"BehandelaarLogin": {
		"v1": &Template{
			Type:               "BehandelaarLogin",
			Version:            "v1",
			Language:           "NL",
			SignerAttributes:   []string{".nuts.agb.agbcode"},
			Template:           `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan {{` + ActingPartyAttr + `}} om namens {{` + LegalEntityAttr + `}} en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van {{` + ValidFromAttr + `}} tot {{` + ValidToAttr + `}}.`,
			TemplateAttributes: []string{ActingPartyAttr, LegalEntityAttr, ValidFromAttr, ValidToAttr},
			Regexp:             `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan (.+) om namens (.+) en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van (.+) tot (.+).`,
		},
		"v2": &Template{
			Type:               "BehandelaarLogin",
			Version:            "v2",
			Language:           "NL",
			SignerAttributes:   StandardSignerAttributes,
			Template:           `NL:BehandelaarLogin:v2 Ondergetekende geeft toestemming aan {{` + ActingPartyAttr + `}} om namens {{` + LegalEntityAttr + `}} en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van {{` + ValidFromAttr + `}} tot {{` + ValidToAttr + `}}.`,
			TemplateAttributes: []string{ActingPartyAttr, LegalEntityAttr, ValidFromAttr, ValidToAttr},
			Regexp:             `NL:BehandelaarLogin:v2 Ondergetekende geeft toestemming aan (.+) om namens (.+) en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van (.+) tot (.+).`,
		},
		"v3": &Template{
			Type:               "BehandelaarLogin",
			Version:            "v3",
			Language:           "NL",
			SignerAttributes:   StandardSignerAttributes,
			Template:           `NL:BehandelaarLogin:v3 Hierbij verklaar ik te handelen in naam van {{` + LegalEntityAttr + `}}. Deze verklaring is geldig van {{` + ValidFromAttr + `}} tot {{` + ValidToAttr + `}}.`,
			TemplateAttributes: []string{LegalEntityAttr, ValidFromAttr, ValidToAttr},
			Regexp:             `NL:BehandelaarLogin:v3 Hierbij verklaar ik te handelen in naam van (.+). Deze verklaring is geldig van (.+) tot (.+).`,
		},
	}},
	"EN": {"PractitionerLogin": {
		"v1": &Template{
			Type:               "PractitionerLogin",
			Version:            "v1",
			Language:           "EN",
			SignerAttributes:   []string{"nuts.agb.agbcode"},
			Template:           `EN:PractitionerLogin:v1 Undersigned gives permission to {{` + ActingPartyAttr + `}} to make request to the Nuts network on behalf of {{` + LegalEntityAttr + `}} and itself. This permission is valid from {{` + ValidFromAttr + `}} until {{` + ValidToAttr + `}}.`,
			TemplateAttributes: []string{ActingPartyAttr, LegalEntityAttr, ValidFromAttr, ValidToAttr},
			Regexp:             `EN:PractitionerLogin:v1 Undersigned gives permission to (.+) to make request to the Nuts network on behalf of (.+) and itself. This permission is valid from (.+) until (.+).`,
		},
		"v2": &Template{
			Type:               "PractitionerLogin",
			Version:            "v2",
			Language:           "EN",
			SignerAttributes:   StandardSignerAttributes,
			Template:           `EN:PractitionerLogin:v2 Undersigned gives permission to {{` + ActingPartyAttr + `}} to make request to the Nuts network on behalf of {{` + LegalEntityAttr + `}} and itself. This permission is valid from {{` + ValidFromAttr + `}} until {{` + ValidToAttr + `}}.`,
			TemplateAttributes: []string{ActingPartyAttr, LegalEntityAttr, ValidFromAttr, ValidToAttr},
			Regexp:             `EN:PractitionerLogin:v2 Undersigned gives permission to (.+) to make request to the Nuts network on behalf of (.+) and itself. This permission is valid from (.+) until (.+).`,
		},
		"v3": &Template{
			Type:               "PractitionerLogin",
			Version:            "v3",
			Language:           "EN",
			SignerAttributes:   StandardSignerAttributes,
			Template:           `EN:PractitionerLogin:v3 I hereby declare to act on behalf of {{` + LegalEntityAttr + `}}. This declaration is valid from {{` + ValidFromAttr + `}} until {{` + ValidToAttr + `}}.`,
			TemplateAttributes: []string{LegalEntityAttr, ValidFromAttr, ValidToAttr},
			Regexp:             `EN:PractitionerLogin:v3 I hereby declare to act on behalf of (.+). This declaration is valid from (.+) until (.+).`,
		},
	}},
}

// TemplateStore contains a list of Contract templates sorted by language, type and version
type TemplateStore map[Language]map[Type]map[Version]*Template

// Get safely searches the template store. When no version is given, v1 is used.
// Returns the template or nil
func (m TemplateStore) Get(cType Type, language Language, version Version) *Template {
	if version == "" {
		version = "v1"
	}
	if template, ok := m[language][cType][version]; ok {
		return template
	}

	return nil
}

func (m TemplateStore) FindFromRawContractText(rawContractText string) (*Template, error) {
	r, _ := regexp.Compile(`^(.{2}):(.+):(v\d+)`)

	matchResult := r.FindSubmatch([]byte(rawContractText))
	if len(matchResult) != 4 {
		return nil, fmt.Errorf("%w: could not extract contract version, language and type", ErrInvalidContractText)
	}

	language := Language(matchResult[1])
	contractType := Type(matchResult[2])
	version := Version(matchResult[3])

	return m.Get(contractType, language, version), nil
}
