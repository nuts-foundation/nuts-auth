package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	core "github.com/nuts-foundation/nuts-go-core"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"
)

// SignedIrmaContract holds the contract and additional methods to parse and validate.
type SignedIrmaContract struct {
	IrmaContract     irma.SignedMessage
	ContractTemplate *ContractTemplate
}

// A IrmaContract is valid when:
//  it has a valid signature
//  it contains a message that is a known ContractTemplate
//  its signature is signed with all attributes required by the ContractTemplate
//  it has a valid time period
//  the acting party named in the contract is the same as the one making the request
type IrmaContractVerifier struct {
	irmaConfig     *irma.Configuration
	validContracts ContractMatrix
}

// ParseSignedIrmaContract parses a json string containing a signed irma contract.
func (cv *IrmaContractVerifier) ParseSignedIrmaContract(rawContract string) (*SignedIrmaContract, error) {
	signedContract := &SignedIrmaContract{}

	if err := json.Unmarshal([]byte(rawContract), &signedContract.IrmaContract); err != nil {
		return nil, fmt.Errorf("could not parse IRMA contract: %w", err)
	}

	if signedContract.IrmaContract.Message == "" {
		return nil, fmt.Errorf("could not parse contract: empty message")
	}

	contractMessage := signedContract.IrmaContract.Message
	contractTemplate, err := NewContractFromMessageContents(contractMessage, cv.validContracts)
	if err != nil {
		return nil, err
	}
	signedContract.ContractTemplate = contractTemplate

	return signedContract, nil
}

func (cv *IrmaContractVerifier) VerifyAll(signedContract *SignedIrmaContract, actingPartyCn string) (*ContractValidationResult, error) {
	res, err := cv.VerifySignature(signedContract)
	if err != nil {
		return res, err
	}
	res, err = cv.ValidateContractContents(signedContract, res, actingPartyCn)
	if err != nil {
		return nil, err
	}
	return cv.verifyRequiredAttributes(signedContract, res)
}

// VerifySignature verifies the IRMA signature.
// Returns a ContractValidationResult
// Note: This method only checks the IRMA crypto, not the attributes used or the contents of the contract.
func (cv *IrmaContractVerifier) VerifySignature(signedContract *SignedIrmaContract) (*ContractValidationResult, error) {
	// Actual verification
	attributes, status, err := signedContract.IrmaContract.Verify(cv.irmaConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("contract signature verification failed: %w", err)
	}

	var disclosedAttributes map[string]string
	// wrapper around irma status result
	validationResult := Invalid
	if status == irma.ProofStatusValid {
		validationResult = Valid

		// a contract needs attributes
		if len(attributes) == 0 {
			return nil, fmt.Errorf("contract does not have any attributes")
		}

		// take the attributes rawvalue and add them to a list.
		disclosedAttributes = make(map[string]string, len(attributes[0]))
		strictMode := core.NutsConfig().InStrictMode()
		for _, att := range attributes[0] {
			// Check schemaManager. Only the pdbf root is accepted in strictMode.
			schemaManager := att.Identifier.Root()
			if strictMode && schemaManager != "pbdf" {
				logrus.Infof("IRMA schemeManager %s is not valid in strictMode", schemaManager)
				validationResult = Invalid
			}
			identifier := att.Identifier.String()
			// strip of the schemeManager
			if i := strings.Index(identifier, "."); i != -1 {
				identifier = identifier[i+1:]
			}
			disclosedAttributes[identifier] = *att.RawValue
		}
	}

	// Assemble and return the validation response
	return &ContractValidationResult{
		validationResult,
		IrmaFormat,
		disclosedAttributes,
	}, nil

}

// ValidateContractContents validates at the actual contract contents.
// Is the timeframe valid and does the common name corresponds with the contract message.
func (cv *IrmaContractVerifier) ValidateContractContents(signedContract *SignedIrmaContract, validationResult *ContractValidationResult, actingPartyCn string) (*ContractValidationResult, error) {
	if validationResult.ValidationResult == Invalid {
		return validationResult, nil
	}

	params, err := signedContract.ContractTemplate.extractParams(signedContract.IrmaContract.Message)
	if err != nil {
		return nil, err
	}

	// Validate time frame
	ok, err := signedContract.ContractTemplate.validateTimeFrame(params)
	if !ok || err != nil {
		validationResult.ValidationResult = Invalid
		return validationResult, err
	}

	// Validate ActingParty Common Name
	ok, err = validateActingParty(params, actingPartyCn)
	if err != nil {
		return nil, err
	}
	if !ok {
		validationResult.ValidationResult = Invalid
		return validationResult, nil
	}

	// Verify if required attributes are used

	return validationResult, nil
}

// ValidateActingParty checks if an given actingParty is equal to the actingParty in a contract
// Usually the given acting party comes from the CN of the client-certificate. This check verifies if the
// contract was actual created by the acting party. This prevents the reuse of the contract by another party.
func validateActingParty(params map[string]string, actingParty string) (bool, error) {
	// If no acting party is given, that is probably an implementation error.
	if actingParty == "" {
		return false, errors.New("actingParty validation failed: actingParty cannot be empty")
	}

	// if no acting party in the params, error
	actingPartyFromContract, ok := params["acting_party"]
	if !ok {
		return false, errors.New("actingParty validation failed: no acting party found in contract params")
	}

	// perform the actual check
	return actingParty == actingPartyFromContract, nil
}

func (cv *IrmaContractVerifier) verifyRequiredAttributes(signedIrmaContract *SignedIrmaContract, validationResult *ContractValidationResult) (*ContractValidationResult, error) {
	if validationResult.ValidationResult == Invalid {
		return validationResult, nil
	}

	contractTemplate := signedIrmaContract.ContractTemplate

	// use a map to ignore duplicates. Allows us to compare lengths
	validationRes := make(map[string]bool)

	requiredAttributes := contractTemplate.SignerAttributes

	for disclosedAtt := range validationResult.DisclosedAttributes {
		// e.g. gemeente.personalData.firstnames
		for _, requiredAttribute := range requiredAttributes {
			// e.g. .gemeente.personalData.firstnames
			if strings.HasSuffix(requiredAttribute, disclosedAtt) {
				validationRes[requiredAttribute] = true
			}
		}
	}

	if len(validationRes) != len(requiredAttributes) {
		foundAttributes := make([]string, len(validationRes))
		for k := range validationRes {
			foundAttributes = append(foundAttributes, k)
		}

		disclosedAttributes := make([]string, len(validationResult.DisclosedAttributes))
		for k := range validationResult.DisclosedAttributes {
			disclosedAttributes = append(disclosedAttributes, k)
		}
		validationResult.ValidationResult = Invalid
		logrus.Infof("missing required attributes in signature. found: %v, needed: %v, disclosed: %v", foundAttributes, requiredAttributes, disclosedAttributes)
	}

	return validationResult, nil
}
