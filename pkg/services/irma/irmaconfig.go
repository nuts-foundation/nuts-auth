/*
 * Nuts auth
 * Copyright (C) 2020. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package irma

import (
	"fmt"
	"io/ioutil"
	"os"
	"sync"

	"github.com/nuts-foundation/nuts-auth/logging"

	"github.com/pkg/errors"
	irma "github.com/privacybydesign/irmago"
	"github.com/privacybydesign/irmago/server"
	"github.com/privacybydesign/irmago/server/irmaserver"
)

// The location the irma webserver will mount
const IrmaMountPath = "/auth/irmaclient"

// ConfSkipAutoUpdateIrmaSchemas is the config key to provide an option to skip auto updating the irma schemas
const ConfSkipAutoUpdateIrmaSchemas = "skipAutoUpdateIrmaSchemas"

// ConfIrmaConfigPath is the config key to provide the irma configuration path
const ConfIrmaConfigPath = "irmaConfigPath"

// ConfIrmaSchemeManager allows selecting an IRMA scheme manager. During development this can ben irma-demo. Production should be pdfb
const ConfIrmaSchemeManager = "irmaSchemeManager"

// create a singleton irma config
var _irmaConfig *irma.Configuration
var configOnce = new(sync.Once)

// create a singleton irma server
var _irmaServer *irmaserver.Server
var serverOnce = new(sync.Once)

// GetIrmaConfig creates and returns an IRMA config.
// The config sets the given irma path or a temporary folder. Then it downloads the schemas.
func GetIrmaConfig(config ValidatorConfig) (irmaConfig *irma.Configuration, err error) {
	irmaConfig = _irmaConfig

	configOnce.Do(func() {
		var configDir string
		configDir, err = irmaConfigDir(config)
		if err != nil {
			return
		}
		logging.Log().Infof("Using irma config dir: %s", configDir)

		options := irma.ConfigurationOptions{}
		irmaConfig, err = irma.NewConfiguration(configDir, options)
		if err != nil {
			return
		}

		logging.Log().Info("Loading irma schemas.")
		if err = irmaConfig.ParseFolder(); err != nil {
			return
		}
		_irmaConfig = irmaConfig
	})
	return
}

// GetIrmaServer creates and starts the irma server instance.
// The server can be used by a IRMA client like the app to handle IRMA sessions
func GetIrmaServer(config ValidatorConfig) (irmaServer *irmaserver.Server, err error) {
	irmaServer = _irmaServer

	serverOnce.Do(func() {
		baseURL := config.PublicURL

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
			Logger:               logging.Log().Logger,
			SchemesPath:          configDir,
			DisableSchemesUpdate: config.SkipAutoUpdateIrmaSchemas,
		}

		logging.Log().Info("Initializing IRMA library...")
		logging.Log().Infof("irma baseurl: %s", config.URL)

		irmaServer, err = irmaserver.New(config)
		if err != nil {
			return
		}
		_irmaServer = irmaServer
	})

	return
}

func irmaConfigDir(config ValidatorConfig) (string, error) {
	path := config.IrmaConfigPath

	if path == "" {
		logging.Log().Info("irma config dir not set, using tmp dir")
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
