package pkg

import (
	"encoding/json"
	"fmt"
	"github.com/mdp/qrterminal/v3"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"os"
	"sync"
	"time"
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

// AuthClient is the interface which should be implemented for clients or mocks
type AuthClient interface {
	CreateContractSession(sessionRequest CreateSessionRequest, actingParty string) (*CreateSessionResult, error)
	ContractSessionStatus(sessionID string) (*SessionStatusResult, error)
	ContractByType(contractType ContractType, language Language, version Version) (*Contract, error)
	ValidateContract(request ValidationRequest) (*ValidationResult, error)
}

// Auth is the main struct of the Auth service
type Auth struct {
	Config                 AuthConfig
	configOnce             sync.Once
	configDone             bool
	ContractSessionHandler ContractSessionHandler
	ContractValidator      ContractValidator
}

// AuthConfig holds all the configuration params
type AuthConfig struct {
	Mode                      string
	Address                   string
	PublicUrl                 string
	IrmaConfigPath            string
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
			Config: AuthConfig{},
		}
	})

	return instance
}

// ErrMissingActingParty is returned when the actingPartyCn is missing from the config
var ErrMissingActingParty = errors.New("missing actingPartyCn")

// ErrMissingPublicUrl is returned when the publicUrl is missing from the config
var ErrMissingPublicUrl = errors.New("missing publicUrl")

// Configure the Auth struct by creating a validator and create an Irma server
func (auth *Auth) Configure() (err error) {
	auth.configOnce.Do(func() {
		if auth.Config.ActingPartyCn == "" {
			err = ErrMissingActingParty
			return
		}

		if auth.Config.PublicUrl == "" {
			err = ErrMissingPublicUrl
			return
		}

		validator := DefaultValidator{
			IrmaServer: GetIrmaServer(auth.Config),
			registry: registry.RegistryInstance(),
			crypto: crypto.CryptoInstance(),
		}
		auth.ContractSessionHandler = validator
		auth.ContractValidator = validator
		auth.configDone = true
	})

	return err
}

// CreateContractSession creates a session based on an IRMA contract. This allows the user to permit the application to
// use the Nuts Network in its name. The user can limit the application in time and scope. By signing it with IRMA other
// nodes in the network can verify the validity of the contract.
func (auth *Auth) CreateContractSession(sessionRequest CreateSessionRequest, actingParty string) (*CreateSessionResult, error) {

	// Step 1: Find the correct contract
	contract, err := ContractByType(sessionRequest.Type, sessionRequest.Language, sessionRequest.Version)
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
	signatureRequest.Disclose = irma.AttributeConDisCon{
		irma.AttributeDisCon{
			irma.AttributeCon{
				irma.NewAttributeRequest(contract.SignerAttributes[0]),
			},
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
		BlackChar: qrterminal.WHITE,
		WhiteChar: qrterminal.BLACK,
		Level: qrterminal.M,
		Writer: os.Stdout,
		QuietZone: 1,
	}
	qrterminal.GenerateWithConfig(qrcode, config)
}

// ContractByType returns a Contract of a certain type, language and version.
// If for the combination of type, version and language no contract can be found, the error is of type ErrContractNotFound
func (auth *Auth) ContractByType(contractType ContractType, language Language, version Version) (*Contract, error) {
	return ContractByType(contractType, language, version)
}

// ContractSessionStatus returns the current session status for a given sessionID.
// If the session is not found, the error is an ErrSessionNotFound and SessionStatusResult is nil
func (auth *Auth) ContractSessionStatus(sessionID string) (*SessionStatusResult, error) {
	if sessionStatus := auth.ContractSessionHandler.SessionStatus(SessionID(sessionID), ""); sessionStatus != nil {
		return sessionStatus, nil
	}
	return nil, fmt.Errorf("sessionID %s: %w", sessionID, ErrSessionNotFound)
}

// ValidateContract validates a given contract. Currently two ContractType's are accepted: Irma and Jwt.
// Both types should be passed as a base64 encoded string in the ContractString of the request paramContractString of the request param
func (auth *Auth) ValidateContract(request ValidationRequest) (*ValidationResult, error) {
	if request.ContractFormat == IrmaFormat {
		return auth.ContractValidator.ValidateContract(request.ContractString, IrmaFormat, request.ActingPartyCN)
	} else if request.ContractFormat == JwtFormat {
		return auth.ContractValidator.ValidateJwt(request.ContractString, request.ActingPartyCN)
	}
	return nil, fmt.Errorf("format %v: %w", request.ContractFormat, ErrUnknownContractFormat)
}
