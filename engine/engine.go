package engine

import (
	"github.com/deepmap/oapi-codegen/pkg/runtime"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/nuts-foundation/nuts-auth/api"
	"github.com/nuts-foundation/nuts-auth/pkg"
	nutsGo "github.com/nuts-foundation/nuts-go-core"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type EchoRouter interface {
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
		Routes: func(router runtime.EchoRouter) {
			// Mount the irma-app routes
			routerWithAny := router.(EchoRouter)
			irmaClientHandler := pkg.GetIrmaServer(authBackend.Config).HandlerFunc()
			irmaEchoHandler := echo.WrapHandler(irmaClientHandler)
			routerWithAny.Any("/auth/irmaclient/*", irmaEchoHandler)

			// Mount the Auth-api routes
			api.RegisterHandlers(router, &api.Wrapper{Auth: authBackend})

			checkConfig(authBackend.Config)

			config := pkg.AuthInstance().Config

			if config.EnableCORS {
				logrus.Debug("enabling CORS")
				routerWithAny.Use(middleware.CORS())
			}
		},
	}
}

func cmd() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "auth",
		Short: "commands related to authentication",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "server",
		Short: "Run standalone auth server",
		Run: func(cmd *cobra.Command, args []string) {
			authEngine := pkg.AuthInstance()
			echoServer := echo.New()
			echoServer.HideBanner = true
			echoServer.Use(middleware.Logger())

			if authEngine.Config.EnableCORS {
				echoServer.Use(middleware.CORS())
			}

			checkConfig(authEngine.Config)

			// Mount the irma-app routes
			irmaClientHandler := pkg.GetIrmaServer(authEngine.Config).HandlerFunc()
			irmaEchoHandler := echo.WrapHandler(irmaClientHandler)
			echoServer.Any("/auth/irmaclient/*", irmaEchoHandler)

			// Mount the Nuts-Auth routes
			api.RegisterHandlers(echoServer, &api.Wrapper{Auth: authEngine})

			// Start the server
			logrus.Fatal(echoServer.Start(authEngine.Config.Address))
		},
	})

	return cmd
}

func checkConfig(config pkg.AuthConfig) {
	if config.IrmaSchemeManager == "" {
		logrus.Fatal("IrmaSchemeManager must be set. Valid options are: [pbdf|irma-demo]")
	}
	if nutsGo.NutsConfig().InStrictMode() && config.IrmaSchemeManager != "pbdf" {
		logrus.Fatal("In strictmode the only valid irma-scheme-manager is 'pbdf'")

	}
}

func flagSet() *pflag.FlagSet {
	flags := pflag.NewFlagSet("auth", pflag.ContinueOnError)

	flags.String(pkg.ConfIrmaSchemeManager, "pbdf", "The IRMA schemeManager to use for attributes. Can be either 'pbdf' or 'irma-demo'")
	flags.String(pkg.ConfAddress, "localhost:1323", "Interface and port for http server to bind to")
	flags.String(pkg.PublicURL, "", "Public URL which can be reached by a users IRMA client")
	flags.String(pkg.ConfMode, "", "server or client, when client it does not start any services so that CLI commands can be used.")
	flags.String(pkg.ConfIrmaConfigPath, "", "path to IRMA config folder. If not set, a tmp folder is created.")
	flags.String(pkg.ConfActingPartyCN, "", "The acting party Common name used in contracts")
	flags.Bool(pkg.ConfAutoUpdateIrmaSchemas, false, "set if you want to skip the auto download of the irma schemas every 60 minutes.")
	flags.Bool(pkg.ConfEnableCORS, false, "Set if you want to allow CORS requests. This is useful when you want browsers to directly communicate with the nuts node.")

	return flags
}
