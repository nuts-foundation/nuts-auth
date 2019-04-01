package cmd

import (
	"context"
	"github.com/nuts-foundation/nuts-proxy/api"
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
	Use:   "serve",
	Short: "Start the service proxy",
	Long:  `Start the service proxy.`,
	Run: func(cmd *cobra.Command, args []string) {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

		apiConfig := &api.Config{Port: httpPort, Logger:logrus.StandardLogger()}
		api := api.New(apiConfig)

		ctx, cancel := context.WithCancel(context.Background())

		go func() {
			api.Start()
		}()

		<-stop
		api.Shutdown(ctx)

		cancel()
	},
}

func init() {
	rootCmd.AddCommand(serveCmd)
	serveCmd.Flags().IntVarP(&httpPort, "httpPort", "p", DefaultHttpPort, "The port the http server should bind to")
}
