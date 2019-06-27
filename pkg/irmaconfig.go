package pkg

import (
	"fmt"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"sync"
)

var irmaInstance *irma.Configuration
var configOnce = new(sync.Once)

// GetIrmaConfig creates and returns an IRMA config.
// The config sets the given irma path or a temporary folder. Then it downloads the schemas.
func GetIrmaConfig(config AuthConfig) *irma.Configuration {
	configOnce.Do(func() {
		irmaConfigFolder := config.IrmaConfigPath
		if irmaConfigFolder == "" {
			var err error
			irmaConfigFolder, err = ioutil.TempDir("", "irmaconfig")
			if err != nil {
				logrus.Panic("Could not create irma tmp dir")
			}
		}
		logrus.Infof("using irma config dir: %s", irmaConfigFolder)
		config, err := irma.NewConfiguration(irmaConfigFolder)
		if err != nil {
			logrus.WithError(err).Panic("Could not create irma config")
			return
		}
		if err := config.DownloadDefaultSchemes(); err != nil {
			logrus.WithError(err).Panic("Could not download default schemes")
			return
		}
		irmaInstance = config
	})
	return irmaInstance
}

var irmaServer *irmaserver.Server
var serverOnce = new(sync.Once)

// GetIrmaServer creates and starts the irma server instance.
// The server can be used by a IRMA client like the app to handle IRMA sessions
func GetIrmaServer(config AuthConfig) *irmaserver.Server {
	serverOnce.Do(func() {
		baseURL := config.PublicUrl

		config := &server.Configuration{
			URL:               fmt.Sprintf("%s/auth/irmaclient", baseURL),
			Logger:            logrus.StandardLogger(),
			IrmaConfiguration: GetIrmaConfig(config),
		}

		logrus.Info("Initializing IRMA library...")
		logrus.Infof("irma baseurl: %s", config.URL)

		srv, err := irmaserver.New(config)
		if err != nil {
			logrus.WithError(err).Panic("Could not initialize IRMA library:")
			return
		}
		irmaServer = srv
	})

	return irmaServer
}
