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

// The location the irma webserver will mount
const IrmaMountPath = "/auth/irmaclient"

// create a singleton irma config
var _irmaConfig *irma.Configuration
var configOnce = new(sync.Once)

// create a singleton irma server
var _irmaServer *irmaserver.Server
var serverOnce = new(sync.Once)

// GetIrmaConfig creates and returns an IRMA config.
// The config sets the given irma path or a temporary folder. Then it downloads the schemas.
func GetIrmaConfig(config AuthConfig) (irmaConfig *irma.Configuration, err error) {
	irmaConfig = _irmaConfig

	configOnce.Do(func() {
		var configDir string
		configDir, err = irmaConfigDir(config)
		if err != nil {
			return
		}
		logrus.Infof("Using irma config dir: %s", configDir)

		options := irma.ConfigurationOptions{}
		irmaConfig, err = irma.NewConfiguration(configDir, options)
		if err != nil {
			return
		}

		if !config.SkipAutoUpdateIrmaSchemas {
			logrus.Infof("Downloading irma schemas. If this annoys you or you want to pin the schemas, set %s", ConfSkipAutoUpdateIrmaSchemas)
			if err = irmaConfig.DownloadDefaultSchemes(); err != nil {
				return
			}
		} else {
			logrus.Info("Loading irma schemas.")
			if err = irmaConfig.ParseFolder(); err != nil {
				return
			}
		}
		_irmaConfig = irmaConfig
	})
	return
}

// GetIrmaServer creates and starts the irma server instance.
// The server can be used by a IRMA client like the app to handle IRMA sessions
func GetIrmaServer(config AuthConfig) (irmaServer *irmaserver.Server, err error) {
	irmaServer = _irmaServer

	serverOnce.Do(func() {
		baseURL := config.PublicUrl

		var configDir string
		configDir, err = irmaConfigDir(config)
		if err != nil {
			return
		}

		irmaConfig, err := GetIrmaConfig(config)
		if err != nil {
			return
		}
		config := &server.Configuration{
			IrmaConfiguration:    irmaConfig,
			URL:                  fmt.Sprintf("%s"+IrmaMountPath, baseURL),
			Logger:               logrus.StandardLogger(),
			SchemesPath:          configDir,
			DisableSchemesUpdate: config.SkipAutoUpdateIrmaSchemas,
		}

		logrus.Info("Initializing IRMA library...")
		logrus.Infof("irma baseurl: %s", config.URL)

		irmaServer, err = irmaserver.New(config)
		if err != nil {
			return
		}
		_irmaServer = irmaServer
	})

	return
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
