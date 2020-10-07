package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mdp/qrterminal/v3"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	irmaService "github.com/nuts-foundation/nuts-auth/pkg/services/irma"
	"github.com/nuts-foundation/nuts-auth/pkg/services/oauth"
	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
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
	CreateContractSession(sessionRequest services.CreateSessionRequest) (*services.CreateSessionResult, error)
	ContractSessionStatus(sessionID string) (*services.SessionStatusResult, error)
	ContractByType(contractType contract.Type, language contract.Language, version contract.Version) (*contract.Template, error)
	ValidateContract(request services.ValidationRequest) (*services.ContractValidationResult, error)
	CreateAccessToken(request services.CreateAccessTokenRequest) (*services.AccessTokenResult, error)
	CreateJwtBearerToken(request services.CreateJwtBearerTokenRequest) (*services.JwtBearerTokenResult, error)
	IntrospectAccessToken(token string) (*services.NutsAccessToken, error)
	KeyExistsFor(legalEntity core.PartyID) bool
	OrganizationNameByID(legalEntity core.PartyID) (string, error)
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

// CreateContractSession creates a session based on an IRMA contract. This allows the user to permit the application to
// use the Nuts Network in its name. The user can limit the application in time and scope. By signing it with IRMA other
// nodes in the network can verify the validity of the contract.
func (auth *Auth) CreateContractSession(sessionRequest services.CreateSessionRequest) (*services.CreateSessionResult, error) {

	// Step 1: Find the correct template
	template, err := auth.ContractTemplates.Find(sessionRequest.Type, sessionRequest.Language, sessionRequest.Version)
	if err != nil {
		return nil, err
	}

	// Step 2: Render the template template with all the correct values
	renderedContract, err := template.Render(map[string]string{
		contract.ActingPartyAttr: auth.Config.ActingPartyCn, // use the acting party from the config as long there is not way of providing it via the api request
		contract.LegalEntityAttr: sessionRequest.LegalEntity,
	}, 0, 60*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("could not render template: %w", err)
	}
	logrus.Debugf("contractMessage: %v", renderedContract.RawContractText)
	if err := renderedContract.Verify(); err != nil {
		return nil, err
	}

	// Step 3: Put the template in an IMRA envelope
	signatureRequest := irma.NewSignatureRequest(renderedContract.RawContractText)
	schemeManager := auth.Config.IrmaSchemeManager

	var attributes irma.AttributeCon
	for _, att := range template.SignerAttributes {
		// Checks if attribute name start with a dot, if so, add the configured scheme manager.
		if strings.Index(att, ".") == 0 {
			att = fmt.Sprintf("%s%s", schemeManager, att)
		}
		attributes = append(attributes, irma.NewAttributeRequest(att))
	}
	signatureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			attributes,
		},
	}

	// Step 4: Start an IRMA session
	sessionPointer, token, err := auth.ContractSessionHandler.StartSession(signatureRequest, func(result *server.SessionResult) {
		logrus.Debugf("session done, result: %s", server.ToJson(result))
	})
	if err != nil {
		return nil, fmt.Errorf("error while creating session: %w", err)
	}
	logrus.Debugf("session created with token: %s", token)

	// Return the sessionPointer and sessionId
	createSessionResult := &services.CreateSessionResult{
		QrCodeInfo: *sessionPointer,
		SessionID:  token,
	}
	jsonResult, _ := json.Marshal(createSessionResult.QrCodeInfo)
	printQrCode(string(jsonResult))
	return createSessionResult, nil
}

func printQrCode(qrcode string) {
	config := qrterminal.Config{
		HalfBlocks: false,
		BlackChar:  qrterminal.WHITE,
		WhiteChar:  qrterminal.BLACK,
		Level:      qrterminal.M,
		Writer:     os.Stdout,
		QuietZone:  1,
	}
	qrterminal.GenerateWithConfig(qrcode, config)
}

// NewByType returns a Contract of a certain type, language and version.
// If for the combination of type, version and language no contract can be found, the error is of type ErrContractNotFound
func (auth *Auth) ContractByType(contractType contract.Type, language contract.Language, version contract.Version) (*contract.Template, error) {
	return auth.ContractTemplates.Find(contractType, language, version)
}

// ContractSessionStatus returns the current session status for a given sessionID.
// If the session is not found, the error is an ErrSessionNotFound and SessionStatusResult is nil
func (auth *Auth) ContractSessionStatus(sessionID string) (*services.SessionStatusResult, error) {
	sessionStatus, err := auth.ContractSessionHandler.SessionStatus(services.SessionID(sessionID))

	if err != nil {
		return nil, fmt.Errorf("sessionID %s: %w", sessionID, err)
	}

	if sessionStatus == nil {
		return nil, fmt.Errorf("sessionID %s: %w", sessionID, services.ErrSessionNotFound)
	}

	return sessionStatus, nil
}

// ValidateContract validates a given contract. Currently two Type's are accepted: Irma and Jwt.
// Both types should be passed as a base64 encoded string in the ContractString of the request paramContractString of the request param
func (auth *Auth) ValidateContract(request services.ValidationRequest) (*services.ContractValidationResult, error) {
	if request.ContractFormat == services.IrmaFormat {
		return auth.ContractValidator.ValidateContract(request.ContractString, services.IrmaFormat, request.ActingPartyCN)
	} else if request.ContractFormat == services.JwtFormat {
		return auth.ContractValidator.ValidateJwt(request.ContractString, request.ActingPartyCN)
	}
	return nil, fmt.Errorf("format %v: %w", request.ContractFormat, contract.ErrUnknownContractFormat)
}

// CreateAccessToken extracts the claims out of the request, checks the validity and builds the access token
func (auth *Auth) CreateAccessToken(request services.CreateAccessTokenRequest) (*services.AccessTokenResult, error) {
	// extract the JwtBearerToken
	jwtBearerToken, err := auth.AccessTokenHandler.ParseAndValidateJwtBearerToken(request.RawJwtBearerToken)
	if err != nil {
		return nil, fmt.Errorf("jwt bearer token validation failed: %w", err)
	}

	// Validate the AuthTokenContainer
	res, err := auth.ContractValidator.ValidateJwt(jwtBearerToken.AuthTokenContainer, request.VendorIdentifier)
	if err != nil {
		return nil, fmt.Errorf("identity tokenen validation failed: %w", err)
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
func (auth *Auth) CreateJwtBearerToken(request services.CreateJwtBearerTokenRequest) (*services.JwtBearerTokenResult, error) {
	return auth.AccessTokenHandler.CreateJwtBearerToken(&request)
}

// IntrospectAccessToken fills the fields in NutsAccessToken from the given Jwt Access Token
func (auth *Auth) IntrospectAccessToken(token string) (*services.NutsAccessToken, error) {
	acClaims, err := auth.AccessTokenHandler.ParseAndValidateAccessToken(token)
	return acClaims, err
}

// KeyExistsFor check if the private key exists on this node by calling the same function on the CryptoClient
func (auth *Auth) KeyExistsFor(legalEntity core.PartyID) bool {
	return auth.Crypto.PrivateKeyExists(cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: legalEntity.String()}))
}

// OrganizationNameByID returns the name of an organisation from the registry
func (auth *Auth) OrganizationNameByID(legalEntity core.PartyID) (string, error) {
	org, err := auth.Registry.OrganizationById(legalEntity)
	if err != nil {
		return "", err
	}
	return org.Name, nil
}
