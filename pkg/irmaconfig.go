package pkg

import (
	"fmt"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
	"io/ioutil"
	"os"
	"sync"
)

var irmaInstance *irma.Configuration
var configOnce = new(sync.Once)

// GetIrmaConfig creates and returns an IRMA config.
// The config sets the given irma path or a temporary folder. Then it downloads the schemas.
func GetIrmaConfig(config AuthConfig) *irma.Configuration {
	configOnce.Do(func() {
		irmaConfigFolder := irmaConfigDir(config)
		logrus.Infof("using irma config dir: %s", irmaConfigFolder)
		irmaConfig, err := irma.NewConfiguration(irmaConfigFolder)
		if err != nil {
			logrus.WithError(err).Panic("Could not create irma config")
			return
		}
		if !config.SkipAutoUpdateIrmaSchemas {
			logrus.Infof("Downloading irma schemas. If this annoys you or you want to pin the schemas, set %s", ConfAutoUpdateIrmaSchemas)
			if err := irmaConfig.DownloadDefaultSchemes(); err != nil {
				logrus.WithError(err).Panic("Could not download default schemes")
				return
			}
		}
		irmaInstance = irmaConfig
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
			URL:                  fmt.Sprintf("%s/auth/irmaclient", baseURL),
			Logger:               logrus.StandardLogger(),
			SchemesPath:          irmaConfigDir(config),
			DisableSchemesUpdate: config.SkipAutoUpdateIrmaSchemas,
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

func irmaConfigDir(config AuthConfig) (path string) {
	path = config.IrmaConfigPath

	if path == "" {
		logrus.Info("irma config dir not set, using tmp dir")
		var err error
		path, err = ioutil.TempDir("", "irmaconfig")
		if err != nil {
			logrus.Panic("Could not create irma tmp dir")
		}
	}
	if err := ensureDirectoryExists(path); err != nil {
		logrus.WithError(err).Panic("Could not create irma config directory")
	}
	return
}

// PathExists checks if the specified path exists.
func pathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return true, err
}

func ensureDirectoryExists(path string) error {
	exists, err := pathExists(path)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return os.MkdirAll(path, 0700)
}
