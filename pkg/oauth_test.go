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
	"fmt"
	"testing"

	"github.com/nuts-foundation/nuts-auth/pkg/services"
	"github.com/stretchr/testify/assert"
)

func TestAuth_CreateAccessToken(t *testing.T) {
	RegisterTestDependencies(t)
	t.Run("invalid jwt", func(t *testing.T) {
		i := &Auth{AccessTokenHandler: MockAccessTokenHandler{claims: nil, parseAndValidateAccessTokenJwtError: fmt.Errorf("validationError")}}
		response, err := i.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "jwt bearer token validation failed")
		}
	})

	t.Run("invalid identity", func(t *testing.T) {
		i := &Auth{
			AccessTokenHandler: MockAccessTokenHandler{claims: &services.NutsJwtBearerToken{}},
			ContractValidator: MockContractValidator{
				jwtResult: services.ContractValidationResult{ValidationResult: services.Invalid},
			},
		}
		response, err := i.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})
		assert.Nil(t, response)
		if assert.NotNil(t, err) {
			assert.Contains(t, err.Error(), "identity validation failed")
		}
	})

	t.Run("it creates a token", func(t *testing.T) {
		expectedAT := "ac"
		i := &Auth{
			ContractValidator: MockContractValidator{
				jwtResult: services.ContractValidationResult{ValidationResult: services.Valid, DisclosedAttributes: map[string]string{"name": "Henk de Vries"}},
			},
			AccessTokenHandler: MockAccessTokenHandler{claims: &services.NutsJwtBearerToken{}, accessToken: expectedAT},
		}

		response, err := i.CreateAccessToken(services.CreateAccessTokenRequest{RawJwtBearerToken: "foo"})
		assert.Nil(t, err)
		if assert.NotNil(t, response) {
			assert.Equal(t, expectedAT, response.AccessToken)
		}
	})
}
