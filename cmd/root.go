package cmd

import (
	"fmt"
	"github.com/mitchellh/go-homedir"
	"github.com/nuts-foundation/nuts-proxy/configuration"
	"github.com/sirupsen/logrus"
	"os"

	"github.com/spf13/cobra"
)

const defaultCfgFile = "nuts-proxy-config"
const defaultCfgFilePath = "$HOME"

var (
	cfgFile     string
	cfgFilePath string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "nuts-service-proxy",
	Short: "The Nuts Service API Proxy",
	Long: `The Nuts Service API Proxy provides a single endpoint 
for vendor space to the several Nuts Services within the service space.
`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	//Run: func(cmd *cobra.Command, args []string) { },
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	//cobra.OnInitialize(initConfig)

	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	rootCmd.PersistentFlags().StringVar(
		&cfgFilePath,
		"config-file-path",
		defaultCfgFilePath,
		"path to configuration file",
	)
	rootCmd.PersistentFlags().StringVar(
		&cfgFile,
		"config-file",
		defaultCfgFile,
		"name of the config file without .yaml extension.",
	)

	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	//rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

// InitConfig reads in config file and ENV variables if set.
func InitConfig(cmd *cobra.Command, args []string) {
	if cfgFilePath == defaultCfgFilePath {
		home, err := homedir.Dir()
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		cfgFilePath = home
	}

	if err := configuration.Initialize(cfgFilePath, cfgFile); err != nil {
		logrus.Errorf("Could not load configuration file %s/%s.yaml", cfgFilePath, cfgFile)
		os.Exit(1)
	}
}
