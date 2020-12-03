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

package irma

import (
	"testing"

	"github.com/nuts-foundation/nuts-auth/pkg/services"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"

	"github.com/nuts-foundation/nuts-auth/testdata"

	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"
)

func TestSignedIrmaContract_VerifySignature(t *testing.T) {

	irmaConfig := func(t *testing.T) *irma.Configuration {
		t.Helper()
		irmaConfig, err := irma.NewConfiguration("../../../testdata/irma", irma.ConfigurationOptions{})
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.NoError(t, irmaConfig.ParseFolder()) {
			t.FailNow()
		}
		return irmaConfig
	}

	irmaContractVerifier := func(t *testing.T) *contractVerifier {
		t.Helper()
		return &contractVerifier{irmaConfig(t), contract.StandardContractTemplates}
	}

	t.Run("an empty contract is Invalid", func(t *testing.T) {
		sic := &SignedIrmaContract{}
		cv := irmaContractVerifier(t)
		res, err := cv.verifySignature(sic)
		res, err = cv.verifyRequiredAttributes(sic, res)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Equal(t, services.Invalid, res.ValidationResult)
	})

	t.Run("a valid contract with a valid IRMA config is Valid", func(t *testing.T) {
		validJsonContract := testdata.ValidIrmaContract
		cv := irmaContractVerifier(t)

		sic, err := cv.parseSignedIrmaContract(validJsonContract)
		if !assert.NoError(t, err) {
			return
		}
		res, err := cv.verifySignature(sic)
		res, err = cv.verifyRequiredAttributes(sic, res)
		assert.NoError(t, err)
		assert.Equal(t, services.Valid, res.ValidationResult)
	})

	t.Run("valid contract signed with wrong attributes is Invalid", func(t *testing.T) {
		validTestContracts := contract.TemplateStore{
			"NL": {"BehandelaarLogin": {
				"v1": &contract.Template{
					Type:               "BehandelaarLogin",
					Version:            "v1",
					Language:           "NL",
					SignerAttributes:   []string{"nuts.missing.attribute", "gemeente.personalData.fullname", "gemeente.personalData.firstnames", "gemeente.personalData.prefix", "gemeente.personalData.familyname"},
					Template:           `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan {{acting_party}} om namens {{legal_entity}} en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van {{valid_from}} tot {{valid_to}}.`,
					TemplateAttributes: []string{"acting_party", "legal_entity", "valid_from", "valid_to"},
					Regexp:             `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan (.+) om namens (.+) en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van (.+) tot (.+).`,
				},
			}}}

		cv := &contractVerifier{irmaConfig(t), validTestContracts}

		validJsonContract := testdata.ValidIrmaContract2
		sic, err := cv.parseSignedIrmaContract(validJsonContract)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		res, err := cv.verifySignature(sic)
		res, err = cv.verifyRequiredAttributes(sic, res)
		assert.NoError(t, err)
		assert.Equal(t, services.Invalid, res.ValidationResult)
	})
}
