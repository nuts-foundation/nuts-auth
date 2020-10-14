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
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/mdp/qrterminal"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
	cryptoTypes "github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/sirupsen/logrus"
)

// ContractClient defines functions for creating and validating signed contracts
type ContractClient interface {
	CreateContractSession(sessionRequest services.CreateSessionRequest) (*services.CreateSessionResult, error)
	ContractSessionStatus(sessionID string) (*services.SessionStatusResult, error)
	ContractByType(contractType contract.Type, language contract.Language, version contract.Version) (*contract.Template, error)
	ValidateContract(request services.ValidationRequest) (*services.ContractValidationResult, error)
	KeyExistsFor(legalEntity core.PartyID) bool
	OrganizationNameByID(legalEntity core.PartyID) (string, error)
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
