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

package engine

import (
	"fmt"
	"github.com/nuts-foundation/nuts-auth/logging"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	apiExperimental "github.com/nuts-foundation/nuts-auth/api/experimental"
	apiV0 "github.com/nuts-foundation/nuts-auth/api/v0"
	"github.com/nuts-foundation/nuts-auth/pkg"
	"github.com/nuts-foundation/nuts-auth/pkg/services/irma"
	nutsGo "github.com/nuts-foundation/nuts-go-core"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type echoRouter interface {
	CONNECT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	DELETE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	GET(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	HEAD(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	OPTIONS(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PATCH(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	POST(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	PUT(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	TRACE(path string, h echo.HandlerFunc, m ...echo.MiddlewareFunc) *echo.Route
	Any(path string, h echo.HandlerFunc, mi ...echo.MiddlewareFunc) []*echo.Route
	Use(middleware ...echo.MiddlewareFunc)
}

// NewAuthEngine creates and returns a new AuthEngine instance.
func NewAuthEngine() *nutsGo.Engine {

	authBackend := pkg.AuthInstance()

	return &nutsGo.Engine{
		Cmd:       cmd(),
		Config:    &authBackend.Config,
		ConfigKey: "auth",
		Configure: authBackend.Configure,
		FlagSet:   flagSet(),
		Name:      "Auth",
		Routes: func(router nutsGo.EchoRouter) {
			// Mount the irma-app routes
			routerWithAny := router.(echoRouter)

			// The Irma router operates on the mount path and does not know about the prefix.
			rewriteFunc := func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, irma.IrmaMountPath) {
					// strip the prefix
					r.URL.Path = strings.Split(r.URL.Path, irma.IrmaMountPath)[1]
				}
				authBackend.Contract.HandlerFunc()(w, r)
			}
			// wrap the http handler in a echo handler
			irmaEchoHandler := echo.WrapHandler(http.HandlerFunc(rewriteFunc))
			routerWithAny.Any(irma.IrmaMountPath+"/*", irmaEchoHandler)

			// Mount the Auth-api routes
			apiV0.RegisterHandlers(router, &apiV0.Wrapper{Auth: authBackend})
			apiExperimental.RegisterHandlers(router, &apiExperimental.Wrapper{Auth: authBackend})

			checkConfig(authBackend.Config)

			config := pkg.AuthInstance().Config

			if config.EnableCORS {
				logging.Log().Debug("enabling CORS")
				routerWithAny.Use(middleware.CORS())
			}
		},
	}
}

func rewriteIrmaRoute() echo.MiddlewareFunc {
	return middleware.Rewrite(map[string]string{irma.IrmaMountPath + "/*": "/$1"})
}

func initEcho(auth *pkg.Auth) (*echo.Echo, error) {
	echoServer := echo.New()
	echoServer.HideBanner = true
	echoServer.Use(middleware.Logger())

	if auth.Config.EnableCORS {
		echoServer.Use(middleware.CORS())
	}
	echoServer.Use(rewriteIrmaRoute())

	// Mount the irma-app routes
	irmaClientHandler := auth.Contract.HandlerFunc()
	irmaEchoHandler := echo.WrapHandler(irmaClientHandler)
	echoServer.Any(irma.IrmaMountPath+"/*", irmaEchoHandler)

	// Mount the Nuts-Auth routes
	apiV0.RegisterHandlers(echoServer, &apiV0.Wrapper{Auth: auth})
	apiExperimental.RegisterHandlers(echoServer, &apiExperimental.Wrapper{Auth: auth})

	// Start the server
	return echoServer, nil

}

func cmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "auth",
		Short: "commands related to authentication",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "server",
		Short: "Run standalone auth server",
		RunE: func(cmd *cobra.Command, args []string) error {
			authEngine := pkg.AuthInstance()
			checkConfig(authEngine.Config)
			echo, err := initEcho(authEngine)
			if err != nil {
				return err
			}
			return echo.Start(authEngine.Config.Address)
		},
	})

	return cmd
}

func checkConfig(config pkg.AuthConfig) {
	if config.IrmaSchemeManager == "" {
		logging.Log().Fatal("IrmaSchemeManager must be set. Valid options are: [pbdf|irma-demo]")
	}
	if nutsGo.NutsConfig().InStrictMode() && config.IrmaSchemeManager != "pbdf" {
		logging.Log().Fatal("In strictmode the only valid irma-scheme-manager is 'pbdf'")
	}
}

func flagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("auth", pflag.ContinueOnError)

	defs := pkg.DefaultAuthConfig()
	flags.String(irma.ConfIrmaSchemeManager, defs.IrmaSchemeManager, fmt.Sprintf("The IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo', default: %s", defs.IrmaSchemeManager))
	flags.String(pkg.ConfAddress, defs.Address, fmt.Sprintf("Interface and port for http server to bind to, default: %s", defs.Address))
	flags.String(pkg.PublicURL, defs.PublicUrl, "Public URL which can be reached by a users IRMA client")
	flags.String(pkg.ConfMode, defs.Mode, "server or client, when client it does not start any services so that CLI commands can be used.")
	flags.String(irma.ConfIrmaConfigPath, defs.IrmaConfigPath, "path to IRMA config folder. If not set, a tmp folder is created.")
	flags.String(pkg.ConfActingPartyCN, defs.ActingPartyCn, "The acting party Common name used in contracts")
	flags.Bool(irma.ConfSkipAutoUpdateIrmaSchemas, defs.SkipAutoUpdateIrmaSchemas, "set if you want to skip the auto download of the irma schemas every 60 minutes.")
	flags.Bool(pkg.ConfEnableCORS, defs.EnableCORS, "Set if you want to allow CORS requests. This is useful when you want browsers to directly communicate with the nuts node.")
	flags.StringSlice(pkg.ConfContractValidators, defs.ContractValidators, "Sets the different contract validators to use")

	return flags
}
