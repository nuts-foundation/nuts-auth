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

	"github.com/nuts-foundation/nuts-auth/pkg/services"
	"github.com/nuts-foundation/nuts-auth/pkg/services/oauth"
	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
)

// this file contains OAuth related service logic previously part of the AuthClient.
// The goal is to move the contents of this file to the oauth service pkg.

// OAuthClient is the client interface for the OAuth service
type OAuthClient interface {
	CreateAccessToken(request services.CreateAccessTokenRequest) (*services.AccessTokenResult, error)
	CreateJwtBearerToken(request services.CreateJwtBearerTokenRequest) (*services.JwtBearerTokenResult, error)
	IntrospectAccessToken(token string) (*services.NutsAccessToken, error)
}

// OAuth is a temporary struct, contents to be migrated to oauth service/accessTokenHandler
type OAuth struct {
	VendorID           core.PartyID
	Crypto             nutscrypto.Client
	Registry           registry.RegistryClient
	ContractValidator  services.ContractValidator
	AccessTokenHandler services.AccessTokenHandler
}

func NewOAuthInstance(vendorID core.PartyID, cryptoClient nutscrypto.Client, registryClient registry.RegistryClient, contractValidator services.ContractValidator) *OAuth {
	return &OAuth{
		VendorID:          vendorID,
		Crypto:            cryptoClient,
		Registry:          registryClient,
		ContractValidator: contractValidator,
	}
}

// Already a good candidate for removal
func (auth *OAuth) Configure() (err error) {
	oauthService := &oauth.OAuthService{
		VendorID: auth.VendorID,
		Crypto:   auth.Crypto,
		Registry: auth.Registry,
	}
	if err = oauthService.Configure(); err != nil {
		return
	}
	auth.AccessTokenHandler = oauthService
	return
}

// CreateAccessToken extracts the claims out of the request, checks the validity and builds the access token
func (auth *OAuth) CreateAccessToken(request services.CreateAccessTokenRequest) (*services.AccessTokenResult, error) {
	// extract the JwtBearerToken
	jwtBearerToken, err := auth.AccessTokenHandler.ParseAndValidateJwtBearerToken(request.RawJwtBearerToken)
	if err != nil {
		return nil, fmt.Errorf("jwt bearer token validation failed: %w", err)
	}

	// Validate the AuthTokenContainer
	res, err := auth.ContractValidator.ValidateJwt(jwtBearerToken.AuthTokenContainer, request.VendorIdentifier)
	if err != nil {
		return nil, fmt.Errorf("identity token validation failed: %w", err)
	}
	if res.ValidationResult == services.Invalid {
		return nil, fmt.Errorf("identity validation failed")
	}

	accessToken, err := auth.AccessTokenHandler.BuildAccessToken(jwtBearerToken, res)
	if err != nil {
		return nil, err
	}

	return &services.AccessTokenResult{AccessToken: accessToken}, nil
}

// CreateJwtBearerToken creates a JwtBearerToken from the given CreateJwtBearerTokenRequest
func (auth *OAuth) CreateJwtBearerToken(request services.CreateJwtBearerTokenRequest) (*services.JwtBearerTokenResult, error) {
	// todo add checks?
	custodian, err := core.ParsePartyID(request.Custodian)
	if err != nil {
		return nil, err
	}
	endpointType := "oauth" // todo

	epoints, err := auth.Registry.EndpointsByOrganizationAndType(custodian, &endpointType)
	if err != nil {
		return nil, err
	}
	if len(epoints) == 0 {
		return nil, oauth.ErrMissingEndpoint
	}

	return auth.AccessTokenHandler.CreateJwtBearerToken(&request, string(epoints[0].Identifier))
}

// IntrospectAccessToken fills the fields in NutsAccessToken from the given Jwt Access Token
func (auth *OAuth) IntrospectAccessToken(token string) (*services.NutsAccessToken, error) {
	acClaims, err := auth.AccessTokenHandler.ParseAndValidateAccessToken(token)
	return acClaims, err
}
