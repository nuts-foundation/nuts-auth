package irma

import (
	"fmt"
	"github.com/nuts-foundation/nuts-proxy/configuration"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"sync"
)

var instance *irma.Configuration
var configOnce = new(sync.Once)

func GetIrmaConfig() *irma.Configuration {
	configOnce.Do(func() {
		irmaConfigFolder := configuration.GetInstance().IrmaConfigPath
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
		instance = config
	})
	return instance
}

var irmaServer *irmaserver.Server
var serverOnce = new(sync.Once)

func GetIrmaServer() *irmaserver.Server {
	serverOnce.Do(func() {
		baseUrl := configuration.GetInstance().HttpAddress

		config := &server.Configuration{
			URL:               fmt.Sprintf("%s/auth/irmaclient", baseUrl),
			Logger:            logrus.StandardLogger(),
			IrmaConfiguration: GetIrmaConfig(),
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
