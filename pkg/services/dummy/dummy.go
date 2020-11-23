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
	"github.com/privacybydesign/irmago/server"
)

// DummyContractFormat is the contract format type
const DummyContractFormat = "dummy"

// DummyVerifiableCredentialType is the dummy verifiable credential type
const DummyVerifiableCredentialType = "DummyVerifiableCredential"

// DummyVerifiablePresentationType is the dummy verifiable presentation type
const DummyVerifiablePresentationType = "DummyVerifiablePresentation"

// SessionCreated represents the session state after creation
const SessionCreated = "created"

// SessionCreated represents the session state after the first SessionStatus call
const SessionInProgress = "in-progress"

// SessionCreated represents the session state after the second SessionStatus call
const SessionCompleted = "completed"

// Dummy is a contract signer and verifier that always succeeds unless you try to use it in strict mode
// The dummy signer is not supposed to be used in a clustered context unless consecutive calls arrive at the same instance
type Dummy struct {
	inStrictMode  bool
	sessions      map[string]contract.SigningSessionRequest
	sessionStatus map[string]string
}

// NutsDummyPresentation is a VerifiablePresentation without valid cryptographic proofs
// It is only usable in non-strict mode.
type NutsDummyPresentation struct {
	contract.VerifiableCredentialBase
	CredentialSubject NutsDummyCredentialSubject
	Proof             NutsDummyProof
}

// NutsDummyCredentialSubject holds the attributes used for the simulated signature
type NutsDummyCredentialSubject struct {
	Initials  NutsDummyCredentialSubjectValue
	Lastname  NutsDummyCredentialSubjectValue
	Birthdate NutsDummyCredentialSubjectValue
	Email     NutsDummyCredentialSubjectValue
}

// NutsDummyCredentialSubjectValue holds the type and value for a specific attribute within the NutsDummyCredentialSubject
type NutsDummyCredentialSubjectValue struct {
	Type  string
	value string
}

// NutsDummyProof holds the Proof generated from the dummy Signer
type NutsDummyProof struct {
	contract.Proof
	// The generated contract
	Contract string
}

type dummySignChallenge struct{}

type dummySigningSessionResult struct {
	Id    string
	State string
}

var errNotEnabled = errors.New("not allowed in strict mode")

var errUnknownSession = errors.New("session unknown")

func (d Dummy) VerifyVP(rawVerifiablePresentation []byte) (*contract.VerificationResult, error) {
	if d.inStrictMode {
		return nil, errNotEnabled
	}

	ndp := NutsDummyPresentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &ndp); err != nil {
		return nil, err
	}

	c, err := contract.ParseContractString(ndp.Proof.Contract, contract.StandardContractTemplates)
	if err != nil {
		return nil, err
	}

	return &contract.VerificationResult{
		State:          contract.Valid,
		ContractFormat: DummyContractFormat,
		DisclosedAttributes: map[string]string{
			"initials":  ndp.CredentialSubject.Initials.value,
			"lastname":  ndp.CredentialSubject.Lastname.value,
			"birthdate": ndp.CredentialSubject.Birthdate.value,
			"email":     ndp.CredentialSubject.Initials.value,
		},
		ContractAttributes: c.Params,
	}, nil
}

func (d Dummy) SessionStatus(session contract.SigningSession) (contract.SigningSessionResult, error) {
	if d.inStrictMode {
		return nil, errNotEnabled
	}

	state, ok := d.sessionStatus[session.ID()]
	if !ok {
		return nil, errUnknownSession
	}

	newState := SessionInProgress
	switch state {
	case SessionInProgress, SessionCompleted:
		newState = SessionCompleted
	}

	return dummySigningSessionResult{
		Id:    session.ID(),
		State: newState,
	}, nil
}

func (d Dummy) StartSession(request contract.SigningSessionRequest, handler server.SessionHandler) (contract.SignChallenge, error) {
	if d.inStrictMode {
		return nil, errNotEnabled
	}
	sessionBytes := make([]byte, 16)
	rand.Reader.Read(sessionBytes)

	sessionId := hex.EncodeToString(sessionBytes)
	d.sessionStatus[sessionId] = "created"
	d.sessions[sessionId] = request

	return dummySignChallenge{}, nil
}
