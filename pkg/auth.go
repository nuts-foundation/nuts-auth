package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"

	"github.com/nuts-foundation/nuts-auth/pkg/types"

	"github.com/nuts-foundation/nuts-auth/pkg/methods"

	"github.com/privacybydesign/irmago/server/irmaserver"

	core "github.com/nuts-foundation/nuts-go-core"

	"github.com/mdp/qrterminal/v3"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
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
	CreateContractSession(sessionRequest types.CreateSessionRequest) (*types.CreateSessionResult, error)
	ContractSessionStatus(sessionID string) (*types.SessionStatusResult, error)
	ContractByType(contractType contract.ContractType, language contract.Language, version contract.Version) (*contract.ContractTemplate, error)
	ValidateContract(request types.ValidationRequest) (*types.ContractValidationResult, error)
	CreateAccessToken(request types.CreateAccessTokenRequest) (*types.AccessTokenResponse, error)
	CreateJwtBearerToken(request types.CreateJwtBearerTokenRequest) (*types.JwtBearerTokenResponse, error)
	IntrospectAccessToken(token string) (*types.NutsAccessToken, error)
	KeyExistsFor(legalEntity core.PartyID) bool
	OrganizationNameByID(legalEntity core.PartyID) (string, error)
}

// Auth is the main struct of the Auth service
type Auth struct {
	Config                 types.AuthConfig
	configOnce             sync.Once
	configDone             bool
	ContractSessionHandler types.ContractSessionHandler
	ContractValidator      types.ContractValidator
	IrmaServer             *irmaserver.Server
	AccessTokenHandler     types.AccessTokenHandler
	Crypto                 crypto.Client
	Registry               registry.RegistryClient
	ValidContracts         contract.ContractMatrix
}

func DefaultAuthConfig() types.AuthConfig {
	return types.AuthConfig{
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
		instance = NewAuthInstance(DefaultAuthConfig(), crypto.CryptoInstance(), registry.RegistryInstance())
	})
	return instance
}

func NewAuthInstance(config types.AuthConfig, cryptoClient crypto.Client, registryClient registry.RegistryClient) *Auth {
	return &Auth{
		Config:         config,
		Crypto:         cryptoClient,
		Registry:       registryClient,
		ValidContracts: contract.Contracts,
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
			if auth.Config.ActingPartyCn == "" {
				err = ErrMissingActingParty
				return
			}
			if auth.Config.PublicUrl == "" {
				err = ErrMissingPublicURL
				return
			}
			auth.ValidContracts = contract.Contracts

			var irmaConfig *irma.Configuration
			if irmaConfig, err = methods.GetIrmaConfig(auth.Config); err != nil {
				return
			}
			var irmaServer *irmaserver.Server
			if irmaServer, err = methods.GetIrmaServer(auth.Config); err != nil {
				return
			}
			auth.IrmaServer = irmaServer
			validator := methods.IrmaValidator{
				IrmaSessionHandler: &types.DefaultIrmaClient{I: irmaServer},
				IrmaConfig:         irmaConfig,
				Registry:           auth.Registry,
				Crypto:             auth.Crypto,
				ValidContracts:     auth.ValidContracts,
			}
			auth.ContractSessionHandler = validator
			auth.ContractValidator = validator
			auth.AccessTokenHandler = validator
			auth.configDone = true
		}
	})

	return err
}

// CreateContractSession creates a session based on an IRMA contract. This allows the user to permit the application to
// use the Nuts Network in its name. The user can limit the application in time and scope. By signing it with IRMA other
// nodes in the network can verify the validity of the contract.
func (auth *Auth) CreateContractSession(sessionRequest types.CreateSessionRequest) (*types.CreateSessionResult, error) {

	// Step 1: Find the correct contract
	contract, err := contract.NewContractByType(sessionRequest.Type, sessionRequest.Language, sessionRequest.Version, contract.Contracts)
	if err != nil {
		return nil, err
	}

	// Step 2: Render the contract template with all the correct values
	message, err := contract.RenderTemplate(map[string]string{
		"acting_party": auth.Config.ActingPartyCn, // use the acting party from the config as long there is not way of providing it via the api request
		"legal_entity": sessionRequest.LegalEntity,
	}, 0, 60*time.Minute)
	logrus.Debugf("contractMessage: %v", message)
	if err != nil {
		return nil, fmt.Errorf("could not render contract template: %w", err)
	}

	// Step 3: Put the contract in an IMRA envelope
	signatureRequest := irma.NewSignatureRequest(message)
	schemeManager := auth.Config.IrmaSchemeManager

	var attributes irma.AttributeCon
	for _, att := range contract.SignerAttributes {
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
	createSessionResult := &types.CreateSessionResult{
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

// NewContractByType returns a ContractTemplate of a certain type, language and version.
// If for the combination of type, version and language no contract can be found, the error is of type ErrContractNotFound
func (auth *Auth) ContractByType(contractType contract.ContractType, language contract.Language, version contract.Version) (*contract.ContractTemplate, error) {
	return contract.NewContractByType(contractType, language, version, auth.ValidContracts)
}

// ContractSessionStatus returns the current session status for a given sessionID.
// If the session is not found, the error is an ErrSessionNotFound and SessionStatusResult is nil
func (auth *Auth) ContractSessionStatus(sessionID string) (*types.SessionStatusResult, error) {
	sessionStatus, err := auth.ContractSessionHandler.SessionStatus(types.SessionID(sessionID))

	if err != nil {
		return nil, fmt.Errorf("sessionID %s: %w", sessionID, err)
	}

	if sessionStatus == nil {
		return nil, fmt.Errorf("sessionID %s: %w", sessionID, types.ErrSessionNotFound)
	}

	return sessionStatus, nil
}

// ValidateContract validates a given contract. Currently two ContractType's are accepted: Irma and Jwt.
// Both types should be passed as a base64 encoded string in the ContractString of the request paramContractString of the request param
func (auth *Auth) ValidateContract(request types.ValidationRequest) (*types.ContractValidationResult, error) {
	if request.ContractFormat == types.IrmaFormat {
		return auth.ContractValidator.ValidateContract(request.ContractString, types.IrmaFormat, request.ActingPartyCN)
	} else if request.ContractFormat == types.JwtFormat {
		return auth.ContractValidator.ValidateJwt(request.ContractString, request.ActingPartyCN)
	}
	return nil, fmt.Errorf("format %v: %w", request.ContractFormat, types.ErrUnknownContractFormat)
}

// CreateAccessToken extracts the claims out of the request, checks the validity and builds the access token
func (auth *Auth) CreateAccessToken(request types.CreateAccessTokenRequest) (*types.AccessTokenResponse, error) {
	// extract the JwtBearerToken
	jwtBearerToken, err := auth.AccessTokenHandler.ParseAndValidateJwtBearerToken(request.RawJwtBearerToken)
	if err != nil {
		return nil, fmt.Errorf("jwt bearer token validation failed: %w", err)
	}

	// Validate the IdentityToken
	res, err := auth.ContractValidator.ValidateJwt(jwtBearerToken.IdentityToken, request.VendorIdentifier)
	if err != nil {
		return nil, fmt.Errorf("identity tokenen validation failed: %w", err)
	}
	if res.ValidationResult == types.Invalid {
		return nil, fmt.Errorf("identity validation failed")
	}

	accessToken, err := auth.AccessTokenHandler.BuildAccessToken(jwtBearerToken, res)
	if err != nil {
		return nil, err
	}

	return &types.AccessTokenResponse{AccessToken: accessToken}, nil
}

// CreateJwtBearerToken creates a JwtBearerToken from the given CreateJwtBearerTokenRequest
func (auth *Auth) CreateJwtBearerToken(request types.CreateJwtBearerTokenRequest) (*types.JwtBearerTokenResponse, error) {
	return auth.AccessTokenHandler.CreateJwtBearerToken(&request)
}

// IntrospectAccessToken fills the fields in NutsAccessToken from the given Jwt Access Token
func (auth *Auth) IntrospectAccessToken(token string) (*types.NutsAccessToken, error) {
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
