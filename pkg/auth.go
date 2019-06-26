package pkg

import (
	"fmt"
	"github.com/go-errors/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

const ConfAddress = "address"
const PublicURL = "publicUrl"

type AuthClient interface {
	CreateContractSession(CreateSessionRequest, actingParty string) (*CreateSessionResult, error)
}

type Auth struct {
	Config                 AuthConfig
	configOnce             sync.Once
	configDone             bool
	contractSessionHandler ContractSessionHandler
}

type AuthConfig struct {
	Address        string
	PublicUrl      string
	IrmaConfigPath string
}

var instance *Auth
var oneBackend sync.Once

func AuthInstance() *Auth {
	oneBackend.Do(func() {
		instance = &Auth{
			Config: AuthConfig{},
		}
	})

	return instance
}

func (auth *Auth) Configure() (err error) {
	auth.configOnce.Do(func() {

		auth.contractSessionHandler = DefaultValidator{
			IrmaServer: GetIrmaServer(auth.Config),
		}

		auth.configDone = true
	})

	return err
}

// CreateContractSession creates a session based on an IRMA contract. This allows the user to permit the application to
// use the Nuts Network in its name. The user can limit the application in time and scope. By signing it with IRMA other
// nodes in the network can verify the validity of the contract.
func (auth Auth) CreateContractSession(sessionRequest CreateSessionRequest, actingParty string) (*CreateSessionResult, error) {

	// Step 1: Find the correct contract
	contract, err := ContractByType(sessionRequest.Type, sessionRequest.Language, sessionRequest.Version)
	if err != nil {
		return nil, err
	}

	// Step 2: Render the contract template with all the correct values
	message, err := contract.RenderTemplate(map[string]string{
		"acting_party": actingParty,
	}, 0, 60*time.Minute)
	logrus.Debugf("contractMessage: %v", message)
	if err != nil {
		logMsg := fmt.Sprintf("Could not render contract template of type %v: %v", contract.Type, err)
		logrus.Error(logMsg)
		return nil, errors.New(logMsg)
	}

	// Step 3: Put the contract in an IMRA envelope
	signatureRequest := &irma.SignatureRequest{
		Message: message,
		DisclosureRequest: irma.DisclosureRequest{
			BaseRequest: irma.BaseRequest{
				Type: irma.ActionSigning,
			},
			Content: irma.AttributeDisjunctionList([]*irma.AttributeDisjunction{{
				Label:      "AGB-Code",
				Attributes: []irma.AttributeTypeIdentifier{irma.NewAttributeTypeIdentifier(contract.SignerAttributes[0])},
			}}),
		},
	}

	// Step 4: Start an IRMA session
	sessionPointer, token, err := auth.contractSessionHandler.StartSession(signatureRequest, func(result *server.SessionResult) {
		logrus.Infof("session done, result: %s", server.ToJson(result))
	})
	if err != nil {
		logrus.Error("error while creating session: ", err)
		return nil, err
	}
	logrus.Debugf("session created with token: %s", token)

	// Return the sessionPointer and sessionId
	createSessionResult := &CreateSessionResult{
		QrCodeInfo: *sessionPointer,
		SessionId:  token,
	}
	return createSessionResult, nil
}

func (auth *Auth) ContractByType(contractType ContractType, language Language, version Version) (*Contract, error) {
	return ContractByType(contractType, language, version)
}
