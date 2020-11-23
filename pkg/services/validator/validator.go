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

package validator

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nuts-foundation/nuts-auth/logging"

	"github.com/mdp/qrterminal/v3"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	irmaService "github.com/nuts-foundation/nuts-auth/pkg/services/irma"
	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

// Config holds all the configuration params
type Config struct {
	Mode                      string
	Address                   string
	PublicUrl                 string
	IrmaConfigPath            string
	IrmaSchemeManager         string
	SkipAutoUpdateIrmaSchemas bool
	ActingPartyCn             string
}

type service struct {
	config                 Config
	contractSessionHandler services.ContractSessionHandler
	contractValidator      services.ContractValidator
	irmaServiceConfig      irmaService.IrmaServiceConfig
	irmaServer             *irmaserver.Server
	crypto                 nutscrypto.Client
	registry               registry.RegistryClient
	verifiers              map[string]contract.Verifier
}

func NewContractInstance(config Config, cryptoClient nutscrypto.Client, registryClient registry.RegistryClient) services.ContractClient {
	return &service{
		config:   config,
		crypto:   cryptoClient,
		registry: registryClient,
	}
}

// Already a good candidate for removal
func (s *service) Configure() (err error) {
	if err = s.configureContracts(); err != nil {
		return
	}

	var (
		irmaConfig *irma.Configuration
		irmaServer *irmaserver.Server
	)

	if irmaServer, irmaConfig, err = s.configureIrma(s.config); err != nil {
		return
	}

	irmaService := irmaService.IrmaService{
		IrmaSessionHandler: &irmaService.DefaultIrmaSessionHandler{I: irmaServer},
		IrmaConfig:         irmaConfig,
		Registry:           s.registry,
		Crypto:             s.crypto,
	}
	s.contractSessionHandler = irmaService
	s.contractValidator = irmaService

	s.verifiers = map[string]contract.Verifier{}
	s.verifiers["irma"] = irmaService

	return
}

func (s *service) VerifyVP(rawVerifiablePresentation []byte) (*contract.VerificationResult, error) {
	vp := contract.VerifiablePresentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &vp); err != nil {
		return nil, err
	}

	if _, ok := s.verifiers[vp.Proof.Type]; !ok {
		return nil, fmt.Errorf("unknown proof type: %s", vp.Proof.Type)
	}

	return s.verifiers[vp.Proof.Type].VerifyVP(rawVerifiablePresentation)
}

// ErrMissingActingParty is returned when the actingPartyCn is missing from the config
var ErrMissingActingParty = errors.New("missing actingPartyCn")

// ErrMissingPublicURL is returned when the publicUrl is missing from the config
var ErrMissingPublicURL = errors.New("missing publicUrl")

// deprecates
func (s *service) configureContracts() (err error) {
	if s.config.ActingPartyCn == "" {
		// todo remove this check in 0.17
		logging.Log().Info("no actingPartyCn configured, this is needed for v2 contracts (deprecated)")
	} else {
		logging.Log().Warn("actingPartyCn is deprecated, please migrate to v3 contracts and remove the config parameter")
	}
	// todo: this is verifier/signer specific
	if s.config.PublicUrl == "" {
		err = ErrMissingPublicURL
		return
	}
	return
}

func (s *service) configureIrma(config Config) (irmaServer *irmaserver.Server, irmaConfig *irma.Configuration, err error) {
	s.irmaServiceConfig = irmaService.IrmaServiceConfig{
		Mode:                      config.Mode,
		Address:                   config.Address,
		PublicUrl:                 config.PublicUrl,
		IrmaConfigPath:            config.IrmaConfigPath,
		IrmaSchemeManager:         config.IrmaSchemeManager,
		SkipAutoUpdateIrmaSchemas: config.SkipAutoUpdateIrmaSchemas,
	}
	if irmaConfig, err = irmaService.GetIrmaConfig(s.irmaServiceConfig); err != nil {
		return
	}
	if irmaServer, err = irmaService.GetIrmaServer(s.irmaServiceConfig); err != nil {
		return
	}
	s.irmaServer = irmaServer
	return
}

// HandlerFunc returns the Irma server handler func
func (s *service) HandlerFunc() http.HandlerFunc {
	return s.irmaServer.HandlerFunc()
}

var ErrMissingOrganizationKey = errors.New("missing organization private key")

// CreateContractSession creates a session based on an IRMA contract. This allows the user to permit the application to
// use the Nuts Network in its name. The user can limit the application in time and scope. By signing it with IRMA other
// nodes in the network can verify the validity of the contract.
func (s *service) CreateContractSession(sessionRequest services.CreateSessionRequest) (*services.CreateSessionResult, error) {

	// Step 1a: Find the correct template
	template, err := contract.StandardContractTemplates.Find(sessionRequest.Type, sessionRequest.Language, sessionRequest.Version)
	if err != nil {
		return nil, err
	}

	// Step 1b find legal entity in crypto
	// todo this should be deprecated when using the oauth flow
	if !s.KeyExistsFor(sessionRequest.LegalEntity) {
		return nil, ErrMissingOrganizationKey
	}

	// translate legal entity to its name
	orgName, err := s.OrganizationNameByID(sessionRequest.LegalEntity)
	if err != nil {
		return nil, err
	}

	// Step 2: Render the template template with all the correct values
	renderedContract, err := template.Render(map[string]string{
		contract.ActingPartyAttr: s.config.ActingPartyCn, // use the acting party from the config as long there is not way of providing it via the api request
		contract.LegalEntityAttr: orgName,
	}, 0, 60*time.Minute)
	if err != nil {
		return nil, fmt.Errorf("could not render template: %w", err)
	}
	logging.Log().Debugf("contractMessage: %v", renderedContract.RawContractText)
	if err := renderedContract.Verify(); err != nil {
		return nil, err
	}

	// Step 3: Put the template in an IMRA envelope
	signatureRequest := irma.NewSignatureRequest(renderedContract.RawContractText)
	schemeManager := s.config.IrmaSchemeManager

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
	sessionPointer, token, err := s.contractSessionHandler.StartSession(signatureRequest, func(result *server.SessionResult) {
		logging.Log().Debugf("session done, result: %s", server.ToJson(result))
	})
	if err != nil {
		return nil, fmt.Errorf("error while creating session: %w", err)
	}
	logging.Log().Debugf("session created with token: %s", token)

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

// ContractSessionStatus returns the current session status for a given sessionID.
// If the session is not found, the error is an ErrSessionNotFound and SessionStatusResult is nil
func (s *service) ContractSessionStatus(sessionID string) (*services.SessionStatusResult, error) {
	sessionStatus, err := s.contractSessionHandler.SessionStatus(services.SessionID(sessionID))

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
func (s *service) ValidateContract(request services.ValidationRequest) (*services.ContractValidationResult, error) {
	var actingPartyCN *string
	if request.ActingPartyCN != "" {
		actingPartyCN = &request.ActingPartyCN
	}

	if request.ContractFormat == services.IrmaFormat {
		return s.contractValidator.ValidateContract(request.ContractString, services.IrmaFormat, actingPartyCN)
	} else if request.ContractFormat == services.JwtFormat {
		return s.contractValidator.ValidateJwt(request.ContractString, actingPartyCN)
	}
	return nil, fmt.Errorf("format %v: %w", request.ContractFormat, contract.ErrUnknownContractFormat)
}

// KeyExistsFor check if the private key exists on this node by calling the same function on the CryptoClient
func (s *service) KeyExistsFor(legalEntity core.PartyID) bool {
	return s.crypto.PrivateKeyExists(cryptoTypes.KeyForEntity(cryptoTypes.LegalEntity{URI: legalEntity.String()}))
}

// OrganizationNameByID returns the name of an organisation from the registry
func (s *service) OrganizationNameByID(legalEntity core.PartyID) (string, error) {
	org, err := s.registry.OrganizationById(legalEntity)
	if err != nil {
		return "", err
	}
	return org.Name, nil
}
