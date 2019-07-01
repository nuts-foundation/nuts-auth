package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
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
		logMsg := fmt.Sprint("Could not parse irma contract")
		logrus.WithError(err).Info(logMsg)
		return nil, errors.New(logMsg)
	}

	return signedContract, nil

}

// Verify the IRMA signature. This method only checks the IRMA crypto, not the contents of the contract.
func (sc *SignedIrmaContract) verifySignature() (*ValidationResult, error) {
	authEngine := AuthInstance()
	// Actual verification
	attributes, status, err := sc.IrmaContract.Verify(GetIrmaConfig(authEngine.Config), nil)

	// error handling
	if err != nil {
		logMsg := "Unable to verify contract signature"
		logrus.WithError(err).Info(logMsg)
		return nil, err
	}

	// wrapper around irma status result
	validationResult := Invalid
	if status == irma.ProofStatusValid {
		validationResult = Valid
	}

	// take the attributes rawvalue and add them to a list.
	disclosedAttributes := make(map[string]string, len(attributes))
	for _, att := range attributes {
		disclosedAttributes[att.Identifier.String()] = *att.RawValue
	}

	// Assemble and return the validation response
	return &ValidationResult{
		validationResult,
		IrmaFormat,
		disclosedAttributes,
	}, nil

}

// Validate the SignedIrmaContract looks at the irma crypto and the actual message such as:
// Is the timeframe valid and does the common name corresponds with the contract message.
func (sc *SignedIrmaContract) Validate(actingPartyCn string) (*ValidationResult, error) {
	// Verify signature:
	verifiedContract, err := sc.verifySignature()
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
	if !ok|| err != nil {
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
		logrus.Error("No acting party provided. Origin of contract cannot be checked.")
		return false, errors.New("actingParty cannot be empty")
	}

	var (
		actingPartyFromContract string
		ok                      bool
	)

	// if no acting party in the params, error
	if actingPartyFromContract, ok = params["acting_party"]; !ok {
		return false, errors.New("no acting party found by contract but one given to verify")
	}

	// perform the actual check
	if actingParty == actingPartyFromContract {
		return true, nil
	}

	// false by default
	return false, nil
}
