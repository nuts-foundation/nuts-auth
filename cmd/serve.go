package cmd

import (
	"github.com/nuts-foundation/nuts-proxy/api"
	"github.com/nuts-foundation/nuts-proxy/configuration"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
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

		appConfig, err := configuration.GetInstance()
		if err != nil {
			logrus.WithError(err).Panicf("Could not get config instance")
		}

		apiConfig := &api.Config{Port: appConfig.HttpPort, Logger: logrus.StandardLogger()}
		api := api.New(apiConfig)

		go func() {
			api.Start()
		}()

		<-stop
		api.Shutdown()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&httpPort, "httpPort", "p", DefaultHttpPort, "The port the http server should bind to")
}
