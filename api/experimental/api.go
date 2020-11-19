package experimental

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/nuts-foundation/nuts-auth/pkg"
)

type Wrapper struct {
	Auth pkg.AuthClient
}

func (w Wrapper) GetContractTemplate(ctx echo.Context, contractType string, params GetContractTemplateParams) error {
	return echo.NewHTTPError(http.StatusNotImplemented)
}

func (w Wrapper) CreateSignSession(ctx echo.Context) error {
	return echo.NewHTTPError(http.StatusNotImplemented)
}

func (w Wrapper) GetSignSessionStatus(ctx echo.Context, sessionPtr string) error {
	return echo.NewHTTPError(http.StatusNotImplemented)
}
