package api

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"
	v1 "github.com/nuts-foundation/nuts-auth/api/v1"
	"github.com/nuts-foundation/nuts-auth/logging"
	core "github.com/nuts-foundation/nuts-go-core"

	"github.com/nuts-foundation/nuts-auth/pkg/contract"
	"github.com/nuts-foundation/nuts-auth/pkg/services"
)

// VerifyAccessToken verifies if a request contains a valid bearer token issued by this server
func (api *Wrapper) VerifyAccessTokenV1(ctx echo.Context, params v1.VerifyAccessTokenV1Params) error {
	if len(params.Authorization) == 0 {
		logging.Log().Warn("No authorization header given")
		return ctx.NoContent(http.StatusForbidden)
	}

	index := strings.Index(strings.ToLower(params.Authorization), bearerPrefix)
	if index != 0 {
		logging.Log().Warn("Authorization does not contain bearer token")
		return ctx.NoContent(http.StatusForbidden)
	}

	token := params.Authorization[len(bearerPrefix):]

	_, err := api.Auth.OAuthClient().IntrospectAccessToken(token)
	if err != nil {
		logging.Log().WithError(err).Warn("Error while inspecting access token")
		return ctx.NoContent(http.StatusForbidden)
	}

	return ctx.NoContent(200)
}

// VerifySignatureV1 handles the VerifySignatureV1 http request.
// It parses the request body, parses the verifiable presentation and calls the ContractClient to verify the VP.
func (w Wrapper) VerifySignatureV1(ctx echo.Context) error {
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

// CreateSignSessionV1 handles the CreateSignSessionV1 http request. It parses the parameters, finds the means handler and returns a session pointer which can be used to monitor the session.
func (w Wrapper) CreateSignSessionV1(ctx echo.Context) error {
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

// GetSignSessionStatusV1 handles the http requests for getting the current status of a signing session.
func (w Wrapper) GetSignSessionStatusV1(ctx echo.Context, sessionPtr string) error {
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

// GetContractTemplateV1 handles http requests for a contract template. The contract is find by language and type.
func (w Wrapper) GetContractTemplateV1(ctx echo.Context, language string, contractType string, params v1.GetContractTemplateV1Params) error {
	var version contract.Version
	if params.Version != nil {
		version = contract.Version(*params.Version)
	}

	c, err := contract.StandardContractTemplates.Find(contract.Type(contractType), contract.Language(language), version)
	if err != nil {
		if errors.Is(err, contract.ErrContractNotFound) {
			return echo.NewHTTPError(http.StatusNotFound, "contract not found")
		}
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	response := ContractTemplateResponse{
		Language: ContractLanguage(c.Language),
		Template: c.Template,
		Type:     ContractType(c.Type),
		Version:  ContractVersion(c.Version),
	}
	return ctx.JSON(http.StatusOK, response)
}

// DrawUpContractV1 handles the http request for drawing up a contract for a given contract template identified by type, language and version.
func (w Wrapper) DrawUpContractV1(ctx echo.Context) error {
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
