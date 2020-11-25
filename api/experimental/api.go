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

type Wrapper struct {
	Auth pkg.AuthClient
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
	response := GetSignSessionStatusResult{Status: sessionStatus.Status()}
	return ctx.JSON(http.StatusOK, response)
}

// GetContractTemplate handles http requests for a contract template. The contract is find by language and type.
func (w Wrapper) GetContractTemplate(ctx echo.Context, language string, contractType string, params GetContractTemplateParams) error {
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
