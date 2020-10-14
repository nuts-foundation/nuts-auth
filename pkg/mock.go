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

package pkg

import (
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	irmaService "github.com/nuts-foundation/nuts-auth/pkg/services/irma"
	irma "github.com/privacybydesign/irmago"
	irmaservercore "github.com/privacybydesign/irmago/server"
)

type MockContractSessionHandler struct {
	SessionStatusResult *services.SessionStatusResult
}

type MockAccessTokenHandler struct {
	claims                              *services.NutsJwtBearerToken
	parseAndValidateAccessTokenJwtError error
	accessToken                         string
	accessTokenError                    error
}

func (m MockAccessTokenHandler) ParseAndValidateJwtBearerToken(acString string) (*services.NutsJwtBearerToken, error) {
	return m.claims, m.parseAndValidateAccessTokenJwtError
}

func (m MockAccessTokenHandler) BuildAccessToken(jwtClaims *services.NutsJwtBearerToken, identityValidationResult *services.ContractValidationResult) (string, error) {
	if m.accessTokenError != nil {
		return "", m.accessTokenError
	}
	if len(m.accessToken) > 0 {
		return m.accessToken, nil
	}
	return "fresh access token", nil
}

type MockContractValidator struct {
	jwtResult  services.ContractValidationResult
	irmaResult services.ContractValidationResult
}

func (m MockAccessTokenHandler) CreateJwtBearerToken(request *services.CreateJwtBearerTokenRequest, _ string) (*services.JwtBearerTokenResult, error) {
	panic("implement me")
}

func (m MockContractValidator) IsInitialized() bool {
	return true
}

func (m MockContractValidator) ValidateContract(contract string, format services.ContractFormat, actingPartyCN string) (*services.ContractValidationResult, error) {
	return &m.irmaResult, nil
}

func (m MockContractValidator) ValidateJwt(contract string, actingPartyCN string) (*services.ContractValidationResult, error) {
	return &m.jwtResult, nil
}

const qrURL = "https://api.nuts-test.example" + irmaService.IrmaMountPath + "/123-session-ref-123"

func (v MockContractSessionHandler) SessionStatus(services.SessionID) (*services.SessionStatusResult, error) {
	return v.SessionStatusResult, nil
}

func (m MockAccessTokenHandler) ParseAndValidateAccessToken(accessToken string) (*services.NutsAccessToken, error) {
	panic("implement me")
}

func (v MockContractSessionHandler) StartSession(request interface{}, handler irmaservercore.SessionHandler) (*irma.Qr, string, error) {
	return &irma.Qr{URL: qrURL, Type: irma.ActionSigning}, "abc-sessionid-abc", nil
}
