package experimental

import (
	"errors"
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-auth/pkg/contract"
)

var _ ServerInterface = (*Wrapper)(nil)

type Wrapper struct {
	Auth pkg.AuthClient
}

func (w Wrapper) CreateSignSession(ctx echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented)
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
	return echo.NewHTTPError(http.StatusNotImplemented)
}
