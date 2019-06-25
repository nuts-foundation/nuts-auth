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

func GetIrmaServer(config AuthConfig) *irmaserver.Server {
	serverOnce.Do(func() {
		baseUrl := config.PublicUrl

		config := &server.Configuration{
			URL:               fmt.Sprintf("%s/auth/irmaclient", baseUrl),
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
