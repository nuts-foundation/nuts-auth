package experimental

import (
	"errors"
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
	core "github.com/nuts-foundation/nuts-go-core"

	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

var _ ServerInterface = (*Wrapper)(nil)

type Wrapper struct {
	Auth pkg.AuthClient
}

func (w Wrapper) CreateSignSession(ctx echo.Context) error {
	requestParams := new(CreateSignSessionRequest)
	if err := ctx.Bind(requestParams); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse request body: %s", err))
	}
	signer := w.Auth.Signer(requestParams.Means)
	if signer == nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("sign means not supported"))
	}

	challenge, err := signer.StartSigningSession(requestParams.Payload)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("unable to create sign challenge: %s", err.Error()))
	}
	response := CreateSignSessionResult{
		Means:      requestParams.Means,
		SessionPtr: challenge.SessionID(),
	}
	return ctx.JSON(http.StatusCreated, response)
}

func (w Wrapper) GetSignSessionStatus(ctx echo.Context, sessionPtr string) error {
	return echo.NewHTTPError(http.StatusNotImplemented)
}

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

func (w Wrapper) DrawUpContract(ctx echo.Context) error {
	params := new(DrawUpContractRequest)
	if err := ctx.Bind(params); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, fmt.Sprintf("Could not parse request body: %s", err))
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

	drawnUpContract, err := w.Auth.ContractNotary().DrawUpContract(*template, orgID)
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
