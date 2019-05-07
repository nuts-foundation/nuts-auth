package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	authirma "github.com/nuts-foundation/nuts-auth/auth/irma"
	irma "github.com/privacybydesign/irmago"
	"github.com/sirupsen/logrus"
)

type SignedIrmaContract struct {
	IrmaContract irma.SignedMessage
}

func ParseIrmaContract(rawContract string) (*SignedIrmaContract, error) {
	signedContract := &SignedIrmaContract{}

	if err := json.Unmarshal([]byte(rawContract), &signedContract.IrmaContract); err != nil {
		logMsg := fmt.Sprint("Could not parse irma contract")
		logrus.WithError(err).Info(logMsg)
		return nil, errors.New(logMsg)
	}

	return signedContract, nil

}

func (sc *SignedIrmaContract) verifySignature() (*ValidationResponse, error) {
	attributes, status, err := sc.IrmaContract.Verify(authirma.GetIrmaConfig(), nil)
	if err != nil {
		logMsg := "Unable to verify contract signature"
		logrus.WithError(err).Info(logMsg)
		return nil, err
	}

	validationResult := Invalid
	if status == irma.ProofStatusValid {
		validationResult = Valid
	}

	disclosedAttributes := make(map[string]string, len(attributes))
	for _, att := range attributes {
		disclosedAttributes[att.Identifier.String()] = *att.RawValue
	}

	return &ValidationResponse{
		validationResult,
		Irma,
		disclosedAttributes,
	}, nil

}

func (sc *SignedIrmaContract) Validate(actingPartyCn string) (*ValidationResponse, error) {
	// Verify signature:
	verifiedContract, err := sc.verifySignature()
	if err != nil {
		return nil, err
	}

	// Parse Nuts contract
	contractMessage := sc.IrmaContract.Message
	contract := ContractFromMessageContents(contractMessage)
	if contract == nil {
		return nil, errors.New("could not find contract")
	}
	params, err := contract.ExtractParams(contractMessage)
	if err != nil {
		return nil, err
	}

	// Validate timeframe
	ok, err := contract.ValidateTimeFrame(params)
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
