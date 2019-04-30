package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	authirma "github.com/nuts-foundation/nuts-proxy/auth/irma"
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
	verifiedContract, err := sc.verifySignature()
	if err != nil {
		return nil, err
	}

	// TODO:
	// Parse Nuts contract
	// Validate timeframe
	// Validate ActingParty Common Name

	return verifiedContract, nil
}
