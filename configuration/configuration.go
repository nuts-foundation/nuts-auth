package configuration

import (
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type NutsProxyConfiguration struct {
	HttpPort       int    `mapstructure:"http_port"`
	HttpAddress    string `mapstructure:"http_address"`
	IrmaConfigPath string `mapstructure:"irma_config_path"`
}

// Default config instance
var config *NutsProxyConfiguration

// Getinstance returns the initialized error object. If there is no initialized object, it returns an error
func GetInstance() (*NutsProxyConfiguration, error) {
	if config == nil {
		return nil, errors.New("cannot get instance of uninitialized config")
	}
	return config, nil
}

// Initialize is the default way of initializing the config. It sets the global config variable and makes sure
// the app can access the config object through the whole application
func Initialize(path, filename string) (err error) {
	config, err = LoadConfigFromFile(path, filename)
	return
}

func LoadConfigFromFile(path, filename string) (*NutsProxyConfiguration, error) {
	config := NutsProxyConfiguration{}
	config.SetDefaults()
	if err := config.LoadFromFile(path, filename); err != nil {
		return nil, err
	}
	return &config, nil
}

func (config *NutsProxyConfiguration) LoadFromFile(path, filename string) error {
	logrus.Infof("Loading config from %s/%s.yaml", path, filename)
	viper.AddConfigPath(path)
	viper.SetConfigName(filename)
	viper.SetConfigType("yaml")
	if err := viper.ReadInConfig(); err != nil {
		return err
	}

	if err := viper.Unmarshal(&config); err != nil {
		return err
	}
	return nil
}

func (config *NutsProxyConfiguration) SetDefaults() {
	config.HttpPort = 3000
	config.IrmaConfigPath = "."
	config.HttpAddress = fmt.Sprintf("localhost:%d", config.HttpPort)
}

func (config *NutsProxyConfiguration) Validate() error {
	return nil
}
