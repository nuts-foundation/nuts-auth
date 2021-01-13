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

package uzi

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

// VerifiablePresentationType contains the string used in the VerifiablePresentation type array to indicate the Uzi means
const VerifiablePresentationType = "NutsUziPresentation"

// Verifier implements the Verifier interface and verifies the VerifiablePresentations of the NutsUziPresentation type.
type Verifier struct {
	UziValidator services.VpProofValueParser
}

// Presentation is a VerifiablePresentation without valid cryptographic proofs
// It is only usable in non-strict mode.
type Presentation struct {
	contract.VerifiablePresentationBase
	Proof Proof
}

// Proof contains the Proof part of the Verifiable presentation of the NutsUziPresentation type
type Proof struct {
	Type       string
	ProofValue string
}

// Verify implements the VerifiablePresentation Verifier interface. It can verify an Uzi VP.
// It checks the signature, the attributes and the contract.
// Returns the contract.VerificationResult or an error if something went wrong.
func (u Verifier) VerifyVP(rawVerifiablePresentation []byte) (*contract.VerificationResult, error) {

	presentation := Presentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &presentation); err != nil {
		return nil, fmt.Errorf("could not parse raw verifiable presentation: %w", err)
	}

	if len(presentation.Proof.ProofValue) == 0 {
		return nil, errors.New("could not verify empty proof")
	}

	typeMatch := false
	for _, pType := range presentation.Type {
		if typeMatch {
			break
		}
		typeMatch = pType == VerifiablePresentationType
	}
	if !typeMatch {
		return nil, fmt.Errorf("could not verify this verification type: '%v', should contain type: %s", presentation.Type, VerifiablePresentationType)
	}

	signedToken, err := u.UziValidator.Parse(presentation.Proof.ProofValue)
	if err != nil {
		return nil, fmt.Errorf("could not verify verifiable presentation: could not parse the proof: %w", err)
	}
	if err := u.UziValidator.Verify(signedToken); err != nil {
		return &contract.VerificationResult{
			State: contract.Invalid,
		}, nil
	}

	disclosedAttributes, err := signedToken.SignerAttributes()
	if err != nil {
		return nil, fmt.Errorf("could not get disclosed attributes from signed contract: %w", err)
	}

	return &contract.VerificationResult{
		State:               contract.Valid,
		ContractFormat:      VerifiablePresentationType,
		DisclosedAttributes: disclosedAttributes,
		ContractAttributes:  signedToken.Contract().Params,
	}, nil
}
