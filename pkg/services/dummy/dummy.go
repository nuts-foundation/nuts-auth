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

// SessionInProgress represents the session state after the first SessionStatus call
const SessionInProgress = "in-progress"

// SessionCompleted represents the session state after the second SessionStatus call
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
	Proof Proof
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
	Initials string
	// Lastname form the signing means
	Lastname string
	// Birthdate form the signing means
	Birthdate string
	// Email form the signing means
	Email string
}

type sessionPointer struct {
	sessionID string
}

func (s sessionPointer) SessionID() string {
	return s.sessionID
}

func (s sessionPointer) Payload() []byte {
	return []byte("dummy")
}

func (s sessionPointer) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		SessionID string `json:"sessionID"`
	}{SessionID: s.sessionID})
}

type signingSessionResult struct {
	ID      string
	State   string
	Request string
}

func (d signingSessionResult) Status() string {
	return d.State
}

func (d signingSessionResult) VerifiablePresentation() (contract.VerifiablePresentation, error) {
	// todo: the contract template should be used to select the dummy attributes to add
	// reqContract := d.Request

	if d.Status() != SessionCompleted {
		return nil, nil
	}

	return Presentation{
		VerifiableCredentialBase: contract.VerifiableCredentialBase{
			Context: []string{contract.VerifiableCredentialContext},
			Type:    []string{contract.VerifiablePresentationType, VerifiablePresentationType},
		},
		Proof: Proof{
			Type:      NoSignatureType,
			Initials:  "I",
			Lastname:  "Tester",
			Birthdate: "1980-01-01",
			Email:     "tester@example.com",
			Contract:  d.Request,
		},
	}, nil
}

var errNotEnabled = errors.New("not allowed in strict mode")

// VerifyVP verifies a verifiablePresentation provided by a byte array.
// It returns the contract.VerificationResult.
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

// SigningSessionStatus looks up the session by the provided sessionID param.
// When the session exists it returns the current state and advances the state to the next one.
// When the session is SessionComplete, it removes the session from the sessionStore.
func (d Dummy) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}

	state, ok := d.Status[sessionID]
	if !ok {
		return nil, services.ErrSessionNotFound
	}

	session, ok := d.Sessions[sessionID]
	if !ok {
		return nil, services.ErrSessionNotFound
	}

	// increase session status everytime this request is made
	switch state {
	case SessionCreated:
		d.Status[sessionID] = SessionInProgress
	case SessionInProgress:
		d.Status[sessionID] = SessionCompleted
	case SessionCompleted:
		delete(d.Status, sessionID)
		delete(d.Sessions, sessionID)
	}
	return signingSessionResult{
		ID:      sessionID,
		State:   state,
		Request: session,
	}, nil
}

// StartSigningSession creates a new signing session based on the rawContractString.
// It creates a sessionID from a random 16 char string and stores the session under this ID in the store.
func (d Dummy) StartSigningSession(rawContractText string) (contract.SessionPointer, error) {
	if d.InStrictMode {
		return nil, errNotEnabled
	}
	sessionBytes := make([]byte, 16)
	rand.Reader.Read(sessionBytes)

	sessionID := hex.EncodeToString(sessionBytes)
	d.Status[sessionID] = SessionCreated
	d.Sessions[sessionID] = rawContractText

	return sessionPointer{
		sessionID: sessionID,
	}, nil
}
