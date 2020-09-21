package pkg

import (
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/pkg/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
	"github.com/sirupsen/logrus"
)

// GetIrmaConfig creates and returns an IRMA config.
// The config sets the given irma path or a temporary folder. Then it downloads the schemas.
func GetIrmaConfig(config AuthConfig) (*irma.Configuration, error) {
	irmaConfigFolder, err := irmaConfigDir(config)
	if err != nil {
		return nil, err
	}
	logrus.Infof("Using irma config dir: %s", irmaConfigFolder)
	options := irma.ConfigurationOptions{}
	irmaConfig, err := irma.NewConfiguration(irmaConfigFolder, options)
	if err != nil {
		return nil, errors.Wrap(err, "could not create irma config")
	}
	if !config.SkipAutoUpdateIrmaSchemas {
		logrus.Infof("Downloading irma schemas. If this annoys you or you want to pin the schemas, set %s", ConfSkipAutoUpdateIrmaSchemas)
		if err := irmaConfig.DownloadDefaultSchemes(); err != nil {
			return nil, errors.Wrap(err, "could not download default schemes")
		}
	} else {
		logrus.Info("Loading irma schemas.")
		if err := irmaConfig.ParseFolder(); err != nil {
			return nil, errors.Wrap(err, "could not load default schemes from disk")
		}
	}
	return irmaConfig, err
}

var irmaServer *irmaserver.Server
var serverOnce = new(sync.Once)

// GetIrmaServer creates and starts the irma server instance.
// The server can be used by a IRMA client like the app to handle IRMA sessions
func GetIrmaServer(config AuthConfig) (*irmaserver.Server, error) {
	var err error
	serverOnce.Do(func() {
		baseURL := config.PublicUrl

		var configDir string
		if configDir, err = irmaConfigDir(config); err != nil {
			return
		}
		config := &server.Configuration{
			URL:                  fmt.Sprintf("%s/auth/irmaclient", baseURL),
			Logger:               logrus.StandardLogger(),
			SchemesPath:          configDir,
			DisableSchemesUpdate: config.SkipAutoUpdateIrmaSchemas,
		}

		logrus.Info("Initializing IRMA library...")
		logrus.Infof("irma baseurl: %s", config.URL)

		var newServer *irmaserver.Server
		newServer, err = irmaserver.New(config)
		if err != nil {
			err = errors.Wrap(err, "could not initialize IRMA library")
			return
		}
		irmaServer = newServer
	})

	return irmaServer, err
}

func irmaConfigDir(config AuthConfig) (string, error) {
	path := config.IrmaConfigPath

	if path == "" {
		logrus.Info("irma config dir not set, using tmp dir")
		var err error
		path, err = ioutil.TempDir("", "irmaconfig")
		if err != nil {
			return "", errors.Wrap(err, "Could not create irma tmp dir")
		}
	}
	if err := ensureDirectoryExists(path); err != nil {
		return "", errors.Wrap(err, "could not create irma config directory")
	}
	return path, nil
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
