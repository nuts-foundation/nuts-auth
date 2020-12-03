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

package experimental

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/labstack/echo/v4"
	core "github.com/nuts-foundation/nuts-go-core"

	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

var _ ServerInterface = (*Wrapper)(nil)

// Wrapper bridges the generated api types and http logic to the internal types and logic.
// It checks required parameters and message body. It converts data from api to internal types.
// Then passes the internal formats to the AuthClient. Converts internal results back to the generated
// Api types. Handles errors and returns the correct http response. It does not perform any business logic.
//
// This is the experimental API. It is used to tests APIs is the wild.
type Wrapper struct {
	Auth pkg.AuthClient
}

// VerifySignature handles the VerifySignature http request.
// It parses the request body, parses the verifiable presentation and calls the ContractClient to verify the VP.
func (w Wrapper) VerifySignature(ctx echo.Context) error {
	requestParams := new(SignatureVerificationRequest)
	if err := ctx.Bind(requestParams); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse request body: %s", err))
	}
	rawVP, err := json.Marshal(requestParams.VerifiablePresentation)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("unable to convert the verifiable presentation: %s", err.Error()))
	}

	validationResult, err := w.Auth.ContractClient().VerifyVP(rawVP)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("unable to verify the verifiable presentation: %s", err.Error()))
	}
	var result SignatureVerificationResponse = validationResult.State == contract.Valid
	return ctx.JSON(http.StatusOK, result)
}

// CreateSignSession handles the CreateSignSession http request. It parses the parameters, finds the means handler and returns a session pointer which can be used to monitor the session.
func (w Wrapper) CreateSignSession(ctx echo.Context) error {
	requestParams := new(CreateSignSessionRequest)
	if err := ctx.Bind(requestParams); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse request body: %s", err))
	}
	createSessionRequest := services.CreateSessionRequest{
		SigningMeans: requestParams.Means,
		Message:      requestParams.Payload,
	}
	pointer, err := w.Auth.ContractClient().CreateSigningSession(createSessionRequest)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("unable to create sign challenge: %s", err.Error()))
	}

	// Convert the session pointer to a map[string]interface{} using json conversion
	// todo: put into separate method
	jsonPointer, err := json.Marshal(pointer)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("unable to convert sessionpointer: %s", err.Error()))
	}
	var keyValPointer map[string]interface{}
	err = json.Unmarshal(jsonPointer, &keyValPointer)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("unable to convert sessionpointer: %s", err.Error()))
	}

	response := CreateSignSessionResult{
		Means:      requestParams.Means,
		SessionPtr: keyValPointer,
	}
	return ctx.JSON(http.StatusCreated, response)
}

// GetSignSessionStatus handles the http requests for getting the current status of a signing session.
func (w Wrapper) GetSignSessionStatus(ctx echo.Context, sessionPtr string) error {
	sessionStatus, err := w.Auth.ContractClient().SigningSessionStatus(sessionPtr)
	if err != nil {
		if errors.Is(err, services.ErrSessionNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, fmt.Sprintf("no active signing session for this sessionPtr found"))
		}
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("unable to retrieve a session status: %s", err.Error()))
	}
	vp, err := sessionStatus.VerifiablePresentation()
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("error while building verifiable presentation: %s", err.Error()))
	}
	var apiVp *VerifiablePresentation
	if vp != nil {
		// Convert the verifiable presentation to a map[string]interface{} using json conversion
		// todo: put into separate method
		jsonVp, err := json.Marshal(vp)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("unable to convert verifiable presentation: %s", err.Error()))
		}
		apiVp = new(VerifiablePresentation)
		err = json.Unmarshal(jsonVp, apiVp)
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, fmt.Sprintf("unable to convert verifiable presentation: %s", err.Error()))
		}
	}
	response := GetSignSessionStatusResult{Status: sessionStatus.Status(), VerifiablePresentation: apiVp}
	return ctx.JSON(http.StatusOK, response)
}

// DrawUpContract handles the http request for drawing up a contract for a given contract template identified by type, language and version.
func (w Wrapper) DrawUpContract(ctx echo.Context) error {
	params := new(DrawUpContractRequest)
	if err := ctx.Bind(params); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse request body: %s", err))
	}

	var (
		vf            time.Time
		validDuration time.Duration
		err           error
	)
	if params.ValidFrom != nil {
		vf, err = time.Parse("2006-01-02T15:04:05-07:00", *params.ValidFrom)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse validFrom: %v", err))
		}
	} else {
		vf = time.Now()
	}

	if params.ValidDuration != nil {
		validDuration, err = time.ParseDuration(*params.ValidDuration)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse validDuration: %v", err))
		}
	}

	template, err := contract.StandardContractTemplates.Find(contract.Type(params.Type), contract.Language(params.Language), contract.Version(params.Version))
	if err != nil {
		if errors.Is(err, contract.ErrContractNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "contract not found")
		}
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	orgID, err := core.ParsePartyID(string(params.LegalEntity))
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Invalid value for param legalEntity: '%s', make sure its in the form 'urn:oid:1.2.3.4:foo'", params.LegalEntity))
	}

	drawnUpContract, err := w.Auth.ContractNotary().DrawUpContract(*template, orgID, vf, validDuration)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("error while drawing up the contract: %s", err.Error()))
	}

	response := ContractResponse{
		Language: ContractLanguage(drawnUpContract.Template.Language),
		Message:  drawnUpContract.RawContractText,
		Type:     ContractType(drawnUpContract.Template.Type),
		Version:  ContractVersion(drawnUpContract.Template.Version),
	}
	return ctx.JSON(http.StatusOK, response)

}
