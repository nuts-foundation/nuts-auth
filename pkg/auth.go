package pkg

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	core "github.com/nuts-foundation/nuts-go-core"

	"github.com/mdp/qrterminal/v3"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	registry2 "github.com/nuts-foundation/nuts-registry/client"
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

// ConfIrmaConfigPath is the config key to provide the irma configuration path
const ConfIrmaConfigPath = "irmaConfigPath"

// ConfAutoUpdateIrmaSchemas is the config key to provide an option to skip auto updating the irma schemas
const ConfAutoUpdateIrmaSchemas = "skipAutoUpdateIrmaSchemas"

const ConfEnableCORS = "enableCORS"

// ConfActingPartyCN is the config key to provide the Acting party common name
const ConfActingPartyCN = "actingPartyCn"

// ConfIrmaSchemeManager allows selecting an IRMA scheme manager. During development this can ben irma-demo. Production should be pdfb
const ConfIrmaSchemeManager = "irmaSchemeManager"

// AuthClient is the interface which should be implemented for clients or mocks
type AuthClient interface {
	CreateContractSession(sessionRequest CreateSessionRequest) (*CreateSessionResult, error)
	ContractSessionStatus(sessionID string) (*SessionStatusResult, error)
	ContractByType(contractType ContractType, language Language, version Version) (*ContractTemplate, error)
	ValidateContract(request ValidationRequest) (*ContractValidationResult, error)
	CreateAccessToken(request CreateAccessTokenRequest) (*AccessTokenResponse, error)
	CreateJwtBearerToken(request CreateJwtBearerTokenRequest) (*JwtBearerTokenResponse, error)
	IntrospectAccessToken(token string) (*NutsAccessToken, error)
	KeyExistsFor(legalEntity string) bool
	OrganizationNameByID(legalEntity string) (string, error)
}

type ContractMatrix map[Language]map[ContractType]map[Version]*ContractTemplate

// Auth is the main struct of the Auth service
type Auth struct {
	Config                 AuthConfig
	configOnce             sync.Once
	configDone             bool
	ContractSessionHandler ContractSessionHandler
	ContractValidator      ContractValidator
	AccessTokenHandler     AccessTokenHandler
	cryptoClient           crypto.Client
	registryClient         registry.RegistryClient
	ValidContracts         ContractMatrix
}

// AuthConfig holds all the configuration params
type AuthConfig struct {
	Mode                      string
	Address                   string
	PublicUrl                 string
	IrmaConfigPath            string
	IrmaSchemeManager         string
	SkipAutoUpdateIrmaSchemas bool
	ActingPartyCn             string
	EnableCORS                bool
}

var instance *Auth
var oneBackend sync.Once

// AuthInstance create an returns a singleton of the Auth struct
func AuthInstance() *Auth {
	oneBackend.Do(func() {
		instance = &Auth{
			Config:         AuthConfig{},
			ValidContracts: Contracts,
		}
	})

	return instance
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

			// these are initialized before nuts-auth
			auth.cryptoClient = crypto.NewCryptoClient()
			auth.registryClient = registry2.NewRegistryClient()
			auth.ValidContracts = Contracts

			validator := DefaultValidator{
				IrmaServer:     &DefaultIrmaClient{I: GetIrmaServer(auth.Config)},
				IrmaConfig:     GetIrmaConfig(auth.Config),
				Registry:       auth.registryClient,
				Crypto:         auth.cryptoClient,
				ValidContracts: auth.ValidContracts,
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
func (auth *Auth) CreateContractSession(sessionRequest CreateSessionRequest) (*CreateSessionResult, error) {

	// Step 1: Find the correct contract
	contract, err := NewContractByType(sessionRequest.Type, sessionRequest.Language, sessionRequest.Version, Contracts)
	if err != nil {
		return nil, err
	}

	// Step 2: Render the contract template with all the correct values
	message, err := contract.renderTemplate(map[string]string{
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
	createSessionResult := &CreateSessionResult{
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
func (auth *Auth) ContractByType(contractType ContractType, language Language, version Version) (*ContractTemplate, error) {
	return NewContractByType(contractType, language, version, auth.ValidContracts)
}

// ContractSessionStatus returns the current session status for a given sessionID.
// If the session is not found, the error is an ErrSessionNotFound and SessionStatusResult is nil
func (auth *Auth) ContractSessionStatus(sessionID string) (*SessionStatusResult, error) {
	sessionStatus, err := auth.ContractSessionHandler.SessionStatus(SessionID(sessionID))

	if err != nil {
		return nil, fmt.Errorf("sessionID %s: %w", sessionID, err)
	}

	if sessionStatus == nil {
		return nil, fmt.Errorf("sessionID %s: %w", sessionID, ErrSessionNotFound)
	}

	return sessionStatus, nil
}

// ValidateContract validates a given contract. Currently two ContractType's are accepted: Irma and Jwt.
// Both types should be passed as a base64 encoded string in the ContractString of the request paramContractString of the request param
func (auth *Auth) ValidateContract(request ValidationRequest) (*ContractValidationResult, error) {
	if request.ContractFormat == IrmaFormat {
		return auth.ContractValidator.ValidateContract(request.ContractString, IrmaFormat, request.ActingPartyCN)
	} else if request.ContractFormat == JwtFormat {
		return auth.ContractValidator.ValidateJwt(request.ContractString, request.ActingPartyCN)
	}
	return nil, fmt.Errorf("format %v: %w", request.ContractFormat, ErrUnknownContractFormat)
}

// CreateAccessToken extracts the claims out of the request, checks the validity and builds the access token
func (auth *Auth) CreateAccessToken(request CreateAccessTokenRequest) (*AccessTokenResponse, error) {
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
	if res.ValidationResult == Invalid {
		return nil, fmt.Errorf("identity validation failed")
	}

	accessToken, err := auth.AccessTokenHandler.BuildAccessToken(jwtBearerToken, res)
	if err != nil {
		return nil, err
	}

	return &AccessTokenResponse{AccessToken: accessToken}, nil
}

// CreateJwtBearerToken creates a JwtBearerToken from the given CreateJwtBearerTokenRequest
func (auth *Auth) CreateJwtBearerToken(request CreateJwtBearerTokenRequest) (*JwtBearerTokenResponse, error) {
	return auth.AccessTokenHandler.CreateJwtBearerToken(&request)
}

// IntrospectAccessToken fills the fields in NutsAccessToken from the given Jwt Access Token
func (auth *Auth) IntrospectAccessToken(token string) (*NutsAccessToken, error) {
	acClaims, err := auth.AccessTokenHandler.ParseAndValidateAccessToken(token)
	return acClaims, err
}

// KeyExistsFor check if the private key exists on this node by calling the same function on the cryptoClient
func (auth *Auth) KeyExistsFor(legalEntity string) bool {
	return auth.cryptoClient.KeyExistsFor(types.LegalEntity{URI: legalEntity})
}

// OrganizationNameByID returns the name of an organisation from the registry
func (auth *Auth) OrganizationNameByID(legalEntity string) (string, error) {
	org, err := auth.registryClient.OrganizationById(legalEntity)
	if err != nil {
		return "", err
	}
	return org.Name, nil
}
