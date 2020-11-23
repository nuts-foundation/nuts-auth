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

package contract

import (
	"github.com/privacybydesign/irmago/server"
)

// Signer is responsible for signing contract signing requests. Signing is done by making use of asynchronous SigningSessions.
type Signer interface {
	SessionStatus(session SigningSession) (SigningSessionResult, error)
	// todo what was the handler for?
	StartSession(request SigningSessionRequest, handler server.SessionHandler) (SignChallenge, error)
}

// SignChallenge is the signing challenge that must be presented to the user
type SignChallenge interface {
}

// SigningSessionRequest
type SigningSessionRequest interface {
}

// SigningSessionResult holds information in the current status of the SigningSession
type SigningSessionResult interface {
}

// SigningSession represents a ongoing session where a user is going to sign a challenge
type SigningSession interface {
	// ID returns the session identifier
	ID() string
}
