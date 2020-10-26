package irma

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/nuts-foundation/nuts-auth/pkg/services"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"

	core "github.com/nuts-foundation/nuts-go-core"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"
)

// SignedIrmaContract holds the contract and additional methods to parse and validate.
type SignedIrmaContract struct {
	IrmaContract irma.SignedMessage
	Contract     *contract.Contract
}

// A IrmaContract is valid when:
//  it has a valid signature
//  it contains a message that is a known Contract
//  its signature is signed with all attributes required by the Contract
//  it has a valid time period
//  the acting party named in the contract is the same as the one making the request
type contractVerifier struct {
	irmaConfig     *irma.Configuration
	validContracts contract.TemplateStore
}

// parseSignedIrmaContract parses a json string containing a signed irma contract.
func (cv *contractVerifier) parseSignedIrmaContract(rawContract string) (*SignedIrmaContract, error) {
	signedIrmaContract := &SignedIrmaContract{}

	if err := json.Unmarshal([]byte(rawContract), &signedIrmaContract.IrmaContract); err != nil {
		return nil, fmt.Errorf("could not parse IRMA contract: %w", err)
	}

	if signedIrmaContract.IrmaContract.Message == "" {
		return nil, fmt.Errorf("could not parse contract: empty message")
	}

	contractMessage := signedIrmaContract.IrmaContract.Message
	c, err := contract.ParseContractString(contractMessage, cv.validContracts)
	if err != nil {
		return nil, err
	}
	signedIrmaContract.Contract = c

	return signedIrmaContract, nil
}

func (cv *contractVerifier) verifyAll(signedContract *SignedIrmaContract, actingPartyCn *string) (*services.ContractValidationResult, error) {
	res, err := cv.verifySignature(signedContract)
	if err != nil {
		return res, err
	}
	res, err = cv.validateContractContents(signedContract, res, actingPartyCn)
	if err != nil {
		return nil, err
	}
	return cv.verifyRequiredAttributes(signedContract, res)
}

// verifySignature verifies the IRMA signature.
// Returns a ContractValidationResult
// Note: This method only checks the IRMA crypto, not the attributes used or the contents of the contract.
func (cv *contractVerifier) verifySignature(signedContract *SignedIrmaContract) (*services.ContractValidationResult, error) {
	// Actual verification
	attributes, status, err := signedContract.IrmaContract.Verify(cv.irmaConfig, nil)
	if err != nil {
		return nil, fmt.Errorf("contract signature verification failed: %w", err)
	}

	var disclosedAttributes map[string]string
	// wrapper around irma status result
	validationResult := services.Invalid
	if status == irma.ProofStatusValid {
		validationResult = services.Valid

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
				validationResult = services.Invalid
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
	return &services.ContractValidationResult{
		validationResult,
		services.IrmaFormat,
		disclosedAttributes,
	}, nil

}

// validateContractContents validates at the actual contract contents.
// Is the timeframe valid and does the common name corresponds with the contract message.
func (cv *contractVerifier) validateContractContents(signedContract *SignedIrmaContract, validationResult *services.ContractValidationResult, actingPartyCn *string) (*services.ContractValidationResult, error) {
	if validationResult.ValidationResult == services.Invalid {
		return validationResult, nil
	}

	// Validate time frame
	if err := signedContract.Contract.Verify(); err != nil {
		validationResult.ValidationResult = services.Invalid
		return validationResult, nil
	}

	// Validate ActingParty Common Name
	// todo remove in 0.17
	if actingPartyCn != nil {
		ok, err := validateActingParty(signedContract.Contract.Params, *actingPartyCn)
		if err != nil {
			return nil, err
		}
		if !ok {
			validationResult.ValidationResult = services.Invalid
			return validationResult, nil
		}
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
	actingPartyFromContract, ok := params[contract.ActingPartyAttr]
	if !ok {
		return false, errors.New("actingParty validation failed: no acting party found in contract params")
	}

	// perform the actual check
	return actingParty == actingPartyFromContract, nil
}

func (cv *contractVerifier) verifyRequiredAttributes(signedIrmaContract *SignedIrmaContract, validationResult *services.ContractValidationResult) (*services.ContractValidationResult, error) {
	if validationResult.ValidationResult == services.Invalid {
		return validationResult, nil
	}

	contractTemplate := signedIrmaContract.Contract.Template

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
		validationResult.ValidationResult = services.Invalid
		logrus.Infof("missing required attributes in signature. found: %v, needed: %v, disclosed: %v", foundAttributes, requiredAttributes, disclosedAttributes)
	}

	return validationResult, nil
}
