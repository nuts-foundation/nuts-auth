package cmd

import (
	"fmt"
	"github.com/nuts-foundation/nuts-auth/engine"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	nutsGo "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/sirupsen/logrus"
	"os"
)

var e = engine.NewAuthEngine()
var rootCmd = e.Cmd

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	c := nutsGo.NutsConfig()
	c.IgnoredPrefixes = append(c.IgnoredPrefixes, e.ConfigKey)
	c.RegisterFlags(rootCmd, e)
	if err := c.Load(rootCmd); err != nil {
		panic(err)
	}

	c.PrintConfig(logrus.StandardLogger())

	if err := c.InjectIntoEngine(e); err != nil {
		panic(err)
	}

	if err := e.Configure(); err != nil {
		panic(err)
	}

	// bootstrap registry and crypto for running nuts-auth as local server
	cr := crypto.CryptoInstance()
	if err := cr.Configure(); err != nil {
		panic(err)
	}

	r := registry.RegistryInstance()
	r.Config.Mode = "server"
	r.Config.Datadir = "tmp"
	r.Config.SyncMode = "fs"
	if err := r.Configure(); err != nil {
		panic(err)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

