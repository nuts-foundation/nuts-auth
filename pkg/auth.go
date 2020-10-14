package pkg

import (
	"errors"
	"sync"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	irmaService "github.com/nuts-foundation/nuts-auth/pkg/services/irma"
	"github.com/nuts-foundation/nuts-auth/pkg/services/oauth"
	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"
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

// AuthClient is the interface which should be implemented for clients or mocks
type AuthClient interface {
	ContractClient
	OAuthClient
}

// Auth is the main struct of the Auth service
type Auth struct {
	Config                 AuthConfig
	configOnce             sync.Once
	configDone             bool
	ContractSessionHandler services.ContractSessionHandler
	ContractValidator      services.ContractValidator
	AccessTokenHandler     services.AccessTokenHandler
	IrmaServiceConfig      irmaService.IrmaServiceConfig
	IrmaServer             *irmaserver.Server
	Crypto                 nutscrypto.Client
	Registry               registry.RegistryClient
	ContractTemplates      contract.TemplateStore
}

func DefaultAuthConfig() AuthConfig {
	return AuthConfig{
		Address:           "localhost:1323",
		IrmaSchemeManager: "pbdf",
	}
}

var instance *Auth
var oneBackend sync.Once

// AuthInstance create an returns a singleton of the Auth struct
func AuthInstance() *Auth {
	if instance != nil {
		return instance
	}
	oneBackend.Do(func() {
		instance = NewAuthInstance(DefaultAuthConfig(), nutscrypto.CryptoInstance(), registry.RegistryInstance())
	})
	return instance
}

func NewAuthInstance(config AuthConfig, cryptoClient nutscrypto.Client, registryClient registry.RegistryClient) *Auth {
	return &Auth{
		Config:            config,
		Crypto:            cryptoClient,
		Registry:          registryClient,
		ContractTemplates: contract.StandardContractTemplates,
	}
}

// ErrMissingActingParty is returned when the actingPartyCn is missing from the config
var ErrMissingActingParty = errors.New("missing actingPartyCn")

// ErrMissingPublicURL is returned when the publicUrl is missing from the config
var ErrMissingPublicURL = errors.New("missing publicUrl")

// Configure the Auth struct by creating a validator and create an Irma server
func (auth *Auth) Configure() (err error) {
	auth.configOnce.Do(func() {
		auth.Config.Mode = core.NutsConfig().GetEngineMode(auth.Config.Mode)
		if auth.Config.Mode == core.ServerEngineMode {

			if err = auth.configureContracts(); err != nil {
				return
			}

			auth.IrmaServiceConfig = irmaService.IrmaServiceConfig{
				Mode:                      auth.Config.Mode,
				Address:                   auth.Config.Address,
				PublicUrl:                 auth.Config.PublicUrl,
				IrmaConfigPath:            auth.Config.IrmaConfigPath,
				IrmaSchemeManager:         auth.Config.IrmaSchemeManager,
				SkipAutoUpdateIrmaSchemas: auth.Config.SkipAutoUpdateIrmaSchemas,
			}

			var (
				irmaConfig *irma.Configuration
				irmaServer *irmaserver.Server
			)

			if irmaServer, irmaConfig, err = auth.configureIrma(); err != nil {
				return
			}

			irmaService := irmaService.IrmaService{
				IrmaSessionHandler: &irmaService.DefaultIrmaSessionHandler{I: irmaServer},
				IrmaConfig:         irmaConfig,
				Registry:           auth.Registry,
				Crypto:             auth.Crypto,
				ContractTemplates:  auth.ContractTemplates,
			}
			auth.ContractSessionHandler = irmaService
			auth.ContractValidator = irmaService

			oauthService := &oauth.OAuthService{
				VendorID: core.NutsConfig().VendorID(),
				Crypto:   auth.Crypto,
				Registry: auth.Registry,
			}
			if err = oauthService.Configure(); err != nil {
				return
			}
			auth.AccessTokenHandler = oauthService
			auth.configDone = true
		}
	})

	return err
}

func (auth *Auth) configureContracts() (err error) {
	if auth.Config.ActingPartyCn == "" {
		err = ErrMissingActingParty
		return
	}
	if auth.Config.PublicUrl == "" {
		err = ErrMissingPublicURL
		return
	}
	auth.ContractTemplates = contract.StandardContractTemplates
	return
}

func (auth *Auth) configureIrma() (irmaServer *irmaserver.Server, irmaConfig *irma.Configuration, err error) {
	auth.IrmaServiceConfig = irmaService.IrmaServiceConfig{
		Mode:                      auth.Config.Mode,
		Address:                   auth.Config.Address,
		PublicUrl:                 auth.Config.PublicUrl,
		IrmaConfigPath:            auth.Config.IrmaConfigPath,
		IrmaSchemeManager:         auth.Config.IrmaSchemeManager,
		SkipAutoUpdateIrmaSchemas: auth.Config.SkipAutoUpdateIrmaSchemas,
	}
	if irmaConfig, err = irmaService.GetIrmaConfig(auth.IrmaServiceConfig); err != nil {
		return
	}
	if irmaServer, err = irmaService.GetIrmaServer(auth.IrmaServiceConfig); err != nil {
		return
	}
	auth.IrmaServer = irmaServer
	return
}
