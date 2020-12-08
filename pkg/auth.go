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
	"sync"
	"time"

	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"

	"github.com/nuts-foundation/nuts-auth/pkg/services"
	"github.com/nuts-foundation/nuts-auth/pkg/services/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services/oauth"
	"github.com/nuts-foundation/nuts-auth/pkg/services/validator"
)

// ConfAddress is the config key for the address the http server listens on
const ConfAddress = "address"

// PublicURL is the config key for the public URL the http/irma server can be discovered
const PublicURL = "publicUrl"

// ConfMode is the config name for the engine mode
const ConfMode = "mode"

const ConfEnableCORS = "enableCORS"

// ConfActingPartyCN is the config key to provide the Acting party common name
const ConfActingPartyCN = "actingPartyCn"

// ConfContractValidators is the config key for defining which contract validators to use
const ConfContractValidators = "contractValidators"

// AuthClient is the interface which should be implemented for clients or mocks
type AuthClient interface {
	// OAuthClient returns an instance of OAuthClient
	OAuthClient() services.OAuthClient
	// ContractClient returns an instance of ContractClient
	ContractClient() services.ContractClient
	// ContractNotary returns an instance of ContractNotary
	ContractNotary() services.ContractNotary
}

// Auth is the main struct of the Auth service
type Auth struct {
	Config              AuthConfig
	configOnce          sync.Once
	configDone          bool
	OAuth               services.OAuthClient
	oneOauthInstance    sync.Once
	Contract            services.ContractClient
	oneContractInstance sync.Once
	Crypto              nutscrypto.Client
	Registry            registry.RegistryClient
	contractNotary      services.ContractNotary
}

// ContractNotary returns an implementation of the ContractNotary interface.
func (auth Auth) ContractNotary() services.ContractNotary {
	return auth.contractNotary
}

// DefaultAuthConfig returns an instance of AuthConfig with the default values.
func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		Address:               "localhost:1323",
		IrmaSchemeManager:     "pbdf",
		ContractValidators:    []string{"irma", "uzi", "dummy"},
		ContractValidDuration: 60 * time.Minute,
	}
}

var instance *Auth
var oneBackend sync.Once

// AuthInstance returns the singleton Auth instance. If this instance does not exists, it creates a new one.
func AuthInstance() *Auth {
	oneBackend.Do(func() {
		instance = NewAuthInstance(DefaultAuthConfig(), nutscrypto.CryptoInstance(), registry.RegistryInstance())
	})
	return instance
}

// NewAuthInstance accepts a AuthConfig with several Nuts Engines and returns an instance of Auth
func NewAuthInstance(config AuthConfig, cryptoClient nutscrypto.Client, registryClient registry.RegistryClient) *Auth {
	return &Auth{
		Config:         config,
		Crypto:         cryptoClient,
		Registry:       registryClient,
		contractNotary: contract.NewContractNotary(registryClient, cryptoClient, config.ContractValidDuration),
	}
}

// OAuthClient returns an instance of OAuthClient
func (auth *Auth) OAuthClient() services.OAuthClient {
	auth.oneOauthInstance.Do(func() {
		auth.OAuth = oauth.NewOAuthService(core.NutsConfig().VendorID(), auth.Crypto, auth.Registry, auth.Contract)
	})
	return auth.OAuth
}

// ContractClient returns an instance of ContractClient
func (auth *Auth) ContractClient() services.ContractClient {
	auth.oneContractInstance.Do(func() {
		cfg := validator.Config{
			Mode:                      auth.Config.Mode,
			Address:                   auth.Config.Address,
			PublicURL:                 auth.Config.PublicUrl,
			IrmaConfigPath:            auth.Config.IrmaConfigPath,
			IrmaSchemeManager:         auth.Config.IrmaSchemeManager,
			SkipAutoUpdateIrmaSchemas: auth.Config.SkipAutoUpdateIrmaSchemas,
			ActingPartyCn:             auth.Config.ActingPartyCn,
			ContractValidators:        auth.Config.ContractValidators,
		}
		auth.Contract = validator.NewContractInstance(cfg, auth.Crypto, auth.Registry)
	})
	return auth.Contract
}

// Configure the Auth struct by creating a validator and create an Irma server
func (auth *Auth) Configure() (err error) {
	auth.configOnce.Do(func() {
		auth.Config.Mode = core.NutsConfig().GetEngineMode(auth.Config.Mode)
		if auth.Config.Mode == core.ServerEngineMode {

			auth.ContractClient()
			if err = auth.Contract.Configure(); err != nil {
				return
			}

			auth.OAuthClient()
			if err = auth.OAuth.Configure(); err != nil {
				return
			}
			auth.configDone = true
		}
	})

	return err
}
