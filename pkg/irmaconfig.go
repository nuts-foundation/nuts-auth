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
func GetIrmaConfig(config AuthConfig) (*irma.Configuration, error) {
	// considering the sync.Once#Do method cannot return anything
	// and this is an initialization function, panic instead of return an error
	configOnce.Do(func() {
		irmaConfigFolder, err := irmaConfigDir(config)
		if err != nil {
			panic(err)
		}
		logrus.Infof("Using irma config dir: %s", irmaConfigFolder)

		options := irma.ConfigurationOptions{}
		newConfig, err := irma.NewConfiguration(irmaConfigFolder, options)
		if err != nil {
			panic(errors.Wrap(err, "could not create irma config"))
		}

		if !config.SkipAutoUpdateIrmaSchemas {
			logrus.Infof("Downloading irma schemas. If this annoys you or you want to pin the schemas, set %s", ConfSkipAutoUpdateIrmaSchemas)
			if err := newConfig.DownloadDefaultSchemes(); err != nil {
				panic(errors.Wrap(err, "could not download default schemes"))
			}
		} else {
			logrus.Info("Loading irma schemas.")
			if err := newConfig.ParseFolder(); err != nil {
				panic(errors.Wrap(err, "could not load default schemes from disk"))
			}
		}
		_irmaConfig = newConfig
	})
	return _irmaConfig, nil
}

// GetIrmaServer creates and starts the irma server instance.
// The server can be used by a IRMA client like the app to handle IRMA sessions
func GetIrmaServer(config AuthConfig) (*irmaserver.Server, error) {
	serverOnce.Do(func() {
		baseURL := config.PublicUrl

		configDir, err := irmaConfigDir(config)
		if err != nil {
			panic(err)
		}

		irmaConfig, err := GetIrmaConfig(config)
		if err != nil {
			panic(err)
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

		newServer, err := irmaserver.New(config)
		if err != nil {
			err = errors.Wrap(err, "could not initialize IRMA library")
			panic(err)
		}
		_irmaServer = newServer
	})
	return _irmaServer, nil
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
