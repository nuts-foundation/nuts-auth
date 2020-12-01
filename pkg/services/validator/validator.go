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

	"github.com/nuts-foundation/nuts-auth/logging"
	"github.com/nuts-foundation/nuts-auth/pkg/services/dummy"

	nutscrypto "github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	irmago "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server/irmaserver"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	"github.com/nuts-foundation/nuts-auth/pkg/services/irma"
)

// Config holds all the configuration params
// todo this doubles the pkg/Config?
type Config struct {
	Mode                      string
	Address                   string
	PublicUrl                 string
	IrmaConfigPath            string
	IrmaSchemeManager         string
	SkipAutoUpdateIrmaSchemas bool
	ActingPartyCn             string
	ContractValidators        []string
}

type service struct {
	config                 Config
	contractSessionHandler services.ContractSessionHandler
	contractValidator      services.ContractValidator
	irmaServiceConfig      irma.ValidatorConfig
	irmaServer             *irmaserver.Server
	crypto                 nutscrypto.Client
	// todo: remove this when the deprecated ValidateJwt is removed
	registry  registry.RegistryClient
	verifiers map[string]contract.Verifier
	signers   map[string]contract.Signer
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
		irmaConfig *irmago.Configuration
		irmaServer *irmaserver.Server
	)

	if irmaServer, irmaConfig, err = s.configureIrma(s.config); err != nil {
		return
	}

	irmaService := irma.IrmaService{
		IrmaSessionHandler: &irma.DefaultIrmaSessionHandler{I: irmaServer},
		IrmaConfig:         irmaConfig,
		// todo: remove this when the deprecated irmaValidatorValidateJwt is removed
		Registry:          s.registry,
		Crypto:            s.crypto,
		IrmaServiceConfig: s.irmaServiceConfig,
	}
	// todo refactor and use signer/verifier
	s.contractSessionHandler = irmaService
	s.contractValidator = irmaService

	s.verifiers = map[string]contract.Verifier{}
	s.signers = map[string]contract.Signer{}

	cvMap := make(map[string]bool, len(s.config.ContractValidators))
	for _, cv := range s.config.ContractValidators {
		cvMap[cv] = true
	}

	// todo config to VP types
	if _, ok := cvMap["irma"]; ok {
		s.verifiers[irma.VerifiablePresentationType] = irmaService
		s.signers[irma.ContractFormat] = irmaService
	}

	if _, ok := cvMap["dummy"]; ok && !core.NutsConfig().InStrictMode() {
		d := dummy.Dummy{
			Sessions: map[string]string{},
			Status:   map[string]string{},
		}
		s.verifiers[dummy.VerifiablePresentationType] = d
		s.signers[dummy.ContractFormat] = d
	}

	return
}

func (s *service) VerifyVP(rawVerifiablePresentation []byte) (*contract.VerificationResult, error) {
	vp := contract.BaseVerifiablePresentation{}
	if err := json.Unmarshal(rawVerifiablePresentation, &vp); err != nil {
		return nil, err
	}

	// remove default type
	types := vp.Type
	n := 0
	for _, x := range types {
		if x != contract.VerifiablePresentationType {
			types[n] = x
			n++
		}
	}
	types = types[:n]

	if len(types) != 1 {
		return nil, errors.New("unprocessable VerifiablePresentation, exactly 1 custom type is expected")
	}
	t := types[0]

	if _, ok := s.verifiers[t]; !ok {
		return nil, fmt.Errorf("unknown VerifiablePresentation type: %s", t)
	}

	return s.verifiers[t].VerifyVP(rawVerifiablePresentation)
}

func (s *service) SigningSessionStatus(sessionID string) (contract.SigningSessionResult, error) {
	for _, signer := range s.signers {
		if r, err := signer.SigningSessionStatus(sessionID); !errors.Is(err, services.ErrSessionNotFound) {
			return r, err
		}
	}
	return nil, services.ErrSessionNotFound
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

func (s *service) configureIrma(config Config) (irmaServer *irmaserver.Server, irmaConfig *irmago.Configuration, err error) {
	s.irmaServiceConfig = irma.ValidatorConfig{
		Address:                   config.Address,
		PublicUrl:                 config.PublicUrl,
		IrmaConfigPath:            config.IrmaConfigPath,
		IrmaSchemeManager:         config.IrmaSchemeManager,
		SkipAutoUpdateIrmaSchemas: config.SkipAutoUpdateIrmaSchemas,
	}
	if irmaConfig, err = irma.GetIrmaConfig(s.irmaServiceConfig); err != nil {
		return
	}
	if irmaServer, err = irma.GetIrmaServer(s.irmaServiceConfig); err != nil {
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

// todo move
var ErrUnknownSigningMeans = errors.New("unknown signing means")

// CreateSigningSession creates a session based on a contract. This allows the user to permit the application to
// use the Nuts Network in its name. By signing it with a cryptographic means other
// nodes in the network can verify the validity of the contract.
func (s *service) CreateSigningSession(sessionRequest services.CreateSessionRequest) (contract.SessionPointer, error) {
	if sessionRequest.Message == "" {
		return nil, errors.New("can not sign an empty message")
	}
	// find correct signer
	signer, ok := s.signers[sessionRequest.SigningMeans]
	if !ok {
		// return nil, ErrUnknownSigningMeans
		// todo remove backwards compatibility
		signer = s.signers["irma"]
	}
	return signer.StartSigningSession(sessionRequest.Message)
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
