package main

import (
	"fmt"
	"github.com/spf13/viper"
)

type NutsProxyConfiguration struct {
	HttpPort       int    `mapstructure:"http_port"`
	HttpAddress    string `mapstructure:"http_address"`
	IrmaConfigPath string `mapstructure:"irma_config_path"`
}

func (config *NutsProxyConfiguration) LoadFromFile(path, filename string) error {
	viper.AddConfigPath(path)
	viper.SetConfigName(filename)
	viper.SetConfigType("json")
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
