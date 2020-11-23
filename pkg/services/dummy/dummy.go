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

package dummy

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

// ContractFormat is the contract format type
const ContractFormat = "dummy"

// VerifiablePresentationType is the dummy verifiable presentation type
const VerifiablePresentationType = "DummyVerifiablePresentation"

// NoSignatureType is a VerifiablePresentation Proof type where no signature is given
const NoSignatureType = "NoSignature"

// SessionCreated represents the session state after creation
const SessionCreated = "created"

// SessionCreated represents the session state after the first SessionStatus call
const SessionInProgress = "in-progress"

// SessionCreated represents the session state after the second SessionStatus call
const SessionCompleted = "completed"

// Dummy is a contract signer and verifier that always succeeds unless you try to use it in strict mode
// The dummy signer is not supposed to be used in a clustered context unless consecutive calls arrive at the same instance
type Dummy struct {
	InStrictMode bool
	Sessions     map[string]string
	Status       map[string]string
}

// Presentation is a VerifiablePresentation without valid cryptographic proofs
// It is only usable in non-strict mode.
type Presentation struct {
	contract.VerifiableCredentialBase
	Proof             Proof
}

// CredentialSubjectValue holds the type and value for a specific attribute within the CredentialSubject
type CredentialSubjectValue struct {
	Type  string
	Value string
}

// Proof holds the Proof generated from the dummy Signer
type Proof struct {
	// Proof type, mandatory
	Type string
	// Contract as how it was presented to the user
	Contract string
	// Initials form the signing means
	Initials  string
	// Lastname form the signing means
	Lastname  string
	// Birthdate form the signing means
	Birthdate string
	// Email form the signing means
	Email     string
}

type signChallenge struct{
	sessionID string
}

func (s signChallenge) SessionID() string {
	return s.sessionID
}

func (s signChallenge) Payload() []byte {
	return []byte("dummy")
}

type signingSessionResult struct {
	Id    string
	State   string
    Request string
}

func (d signingSessionResult) VerifiablePresentation() (contract.VerifiablePresentation, error) {
	// todo: the contract template should be used to select the dummy attributes to add
	// reqContract := d.Request.Contract()

	return Presentation{
		VerifiableCredentialBase: contract.VerifiableCredentialBase{
			Context: contract.VerifiableCredentialContext,
			Type:    []string{contract.VerifiablePresentationType, VerifiablePresentationType},
		},
		Proof: Proof {
			Type: NoSignatureType,
			Initials:  "I",
			Lastname:  "Tester",
			Birthdate: "1980-01-01",
			Email:     "tester@example.com",
		},
	}, nil
}

var errNotEnabled = errors.New("not allowed in strict mode")

func (d Dummy) VerifyVP(rawVerifiablePresentation []byte) (*contract.VerificationResult, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}

	ndp := Presentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &ndp); err != nil {
		return nil, err
	}

	c, err := contract.ParseContractString(ndp.Proof.Contract, contract.StandardContractTemplates)
	if err != nil {
		return nil, err
	}

	return &contract.VerificationResult{
		State:          contract.Valid,
		ContractFormat: ContractFormat,
		DisclosedAttributes: map[string]string{
			"initials":  ndp.Proof.Initials,
			"lastname":  ndp.Proof.Lastname,
			"birthdate": ndp.Proof.Birthdate,
			"email":     ndp.Proof.Initials,
		},
		ContractAttributes: c.Params,
	}, nil
}

func (d Dummy) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}

	state, ok := d.Status[sessionID]
	if !ok {
		return nil, services.ErrSessionNotFound
	}

	newState := SessionInProgress
	switch state {
	case SessionInProgress, SessionCompleted:
		newState = SessionCompleted
	}

	return signingSessionResult{
		Id:      sessionID,
		State:   newState,
		Request: d.Sessions[sessionID],
	}, nil
}

func (d Dummy) StartSigningSession(rawContractText string) (contract.SignChallenge, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}
	sessionBytes := make([]byte, 16)
	rand.Reader.Read(sessionBytes)

	sessionId := hex.EncodeToString(sessionBytes)
	d.Status[sessionId] = SessionCreated
	d.Sessions[sessionId] = rawContractText

	return signChallenge{
		sessionID: sessionId,
	}, nil
}
