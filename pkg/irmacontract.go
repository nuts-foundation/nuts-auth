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
	IrmaContract irma.SignedMessage
}

// ParseIrmaContract parses a json string containing a signed irma contract.
func ParseIrmaContract(rawContract string) (*SignedIrmaContract, error) {
	signedContract := &SignedIrmaContract{}

	if err := json.Unmarshal([]byte(rawContract), &signedContract.IrmaContract); err != nil {
		return nil, fmt.Errorf("could not parse IRMA contract: %w", err)
	}

	return signedContract, nil

}

// Verify the IRMA signature. This method only checks the IRMA crypto, not the contents of the contract.
func (sc *SignedIrmaContract) verifySignature(configuration *irma.Configuration) (*ContractValidationResult, error) {
	// Actual verification
	attributes, status, err := sc.IrmaContract.Verify(configuration, nil)
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
		for _, att := range attributes[0] {
			// Check schemaManager. Only the pdbf root is accepted in strictMode.
			schemaManager := att.Identifier.Root()
			strictMode := core.NutsConfig().InStrictMode()
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

// Validate the SignedIrmaContract looks at the irma crypto and the actual message such as:
// Is the timeframe valid and does the common name corresponds with the contract message.
func (sc *SignedIrmaContract) Validate(actingPartyCn string, configuration *irma.Configuration) (*ContractValidationResult, error) {
	// Verify signature:
	verifiedContract, err := sc.verifySignature(configuration)
	if err != nil {
		return nil, err
	}

	// Parse Nuts contract
	contractMessage := sc.IrmaContract.Message
	contract, err := ContractFromMessageContents(contractMessage)
	if err != nil {
		return nil, err
	}
	params, err := contract.extractParams(contractMessage)
	if err != nil {
		return nil, err
	}

	// Validate timeframe
	ok, err := contract.validateTimeFrame(params)
	if !ok || err != nil {
		verifiedContract.ValidationResult = Invalid
		return verifiedContract, err
	}

	// Validate ActingParty Common Name
	ok, err = validateActingParty(params, actingPartyCn)
	if err != nil {
		return nil, err
	}
	if !ok {
		verifiedContract.ValidationResult = Invalid
		return verifiedContract, nil
	}

	return verifiedContract, nil
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
