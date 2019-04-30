package cmd

import (
	"github.com/nuts-foundation/nuts-proxy/api"
	"github.com/nuts-foundation/nuts-proxy/api/auth"
	authvalidator "github.com/nuts-foundation/nuts-proxy/auth"
	"github.com/nuts-foundation/nuts-proxy/auth/irma"
	"github.com/nuts-foundation/nuts-proxy/configuration"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"net/url"
	"os"
	"os/signal"
	"syscall"
)

const DefaultHttpPort = 3000

var httpPort int

// serveCmd represents the serve command
var serveCmd = &cobra.Command{
	Use:              "serve",
	Short:            "Start the service proxy",
	Long:             `Start the service proxy.`,
	PersistentPreRun: InitConfig,
	Run: func(cmd *cobra.Command, args []string) {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

		appConfig := configuration.GetInstance()
		httpBaseUrl, err := url.Parse(appConfig.HttpAddress)
		if err != nil {
			logrus.Panic("Could not parse http address from config. Make sure it is a valid URL")
		}

		apiConfig := &api.Config{Port: appConfig.HttpPort, Logger: logrus.StandardLogger(), BaseUrl: httpBaseUrl}
		api := api.New(apiConfig)
		api.Mount("/auth", auth.New(appConfig, authvalidator.DefaultValidator{}).Handler())
		api.Mount("/auth/irmaclient", irma.GetIrmaServer().HandlerFunc())

		go func() {
			<-stop
			logrus.Info("Received SIGTERM")
			api.Shutdown()
		}()

		api.Start()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&httpPort, "httpPort", "p", DefaultHttpPort, "The port the http server should bind to")
}
