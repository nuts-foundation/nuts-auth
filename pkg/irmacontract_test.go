package pkg

import (
	"testing"

	"github.com/nuts-foundation/nuts-auth/testdata"

	irma "github.com/privacybydesign/irmago"
	"github.com/stretchr/testify/assert"
)

func TestSignedIrmaContract_VerifySignature(t *testing.T) {

	irmaConfig := func(t *testing.T) *irma.Configuration {
		t.Helper()
		irmaConfig, err := irma.NewConfiguration("../testdata/irma")
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		if !assert.NoError(t, irmaConfig.ParseFolder()) {
			t.FailNow()
		}
		return irmaConfig
	}

	irmaContractVerifier := func(t *testing.T) *IrmaContractVerifier {
		t.Helper()
		return &IrmaContractVerifier{irmaConfig(t), Contracts}
	}

	t.Run("an empty contract is Invalid", func(t *testing.T) {
		sic := &SignedIrmaContract{}
		cv := irmaContractVerifier(t)
		res, err := cv.VerifySignature(sic)
		res, err = cv.verifyRequiredAttributes(sic, res)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		assert.Equal(t, Invalid, res.ValidationResult)
	})

	t.Run("a valid contract with a valid IRMA config is Valid", func(t *testing.T) {
		validJsonContract := testdata.ValidIrmaContract
		cv := irmaContractVerifier(t)

		sic, err := cv.ParseSignedIrmaContract(validJsonContract)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		res, err := cv.VerifySignature(sic)
		res, err = cv.verifyRequiredAttributes(sic, res)
		assert.NoError(t, err)
		assert.Equal(t, Valid, res.ValidationResult)
	})

	t.Run("valid contract signed with wrong attributes is Invalid", func(t *testing.T) {
		validTestContracts := ContractMatrix{
			"NL": {"BehandelaarLogin": {
				"v1": &ContractTemplate{
					Type:               "BehandelaarLogin",
					Version:            "v1",
					Language:           "NL",
					SignerAttributes:   []string{"nuts.missing.attribute", "gemeente.personalData.fullname", "gemeente.personalData.firstnames", "gemeente.personalData.prefix", "gemeente.personalData.familyname"},
					Template:           `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan {{acting_party}} om namens {{legal_entity}} en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van {{valid_from}} tot {{valid_to}}.`,
					TemplateAttributes: []string{"acting_party", "legal_entity", "valid_from", "valid_to"},
					Regexp:             `NL:BehandelaarLogin:v1 Ondergetekende geeft toestemming aan (.+) om namens (.+) en ondergetekende het Nuts netwerk te bevragen. Deze toestemming is geldig van (.+) tot (.+).`,
				},
			}}}

		cv := &IrmaContractVerifier{irmaConfig(t), validTestContracts}

		validJsonContract := testdata.ValidIrmaContract2
		sic, err := cv.ParseSignedIrmaContract(validJsonContract)
		if !assert.NoError(t, err) {
			t.FailNow()
		}
		res, err := cv.VerifySignature(sic)
		res, err = cv.verifyRequiredAttributes(sic, res)
		assert.NoError(t, err)
		assert.Equal(t, Invalid, res.ValidationResult)
	})
}
