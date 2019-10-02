package cmd

import (
	"fmt"
	"github.com/nuts-foundation/nuts-auth/engine"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	nutsGo "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/pkg/db"
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

	le := types.LegalEntity{URI: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000"}
	cr.GenerateKeyPairFor(le)
	pub, _ := cr.PublicKey(le)

	r.RegisterOrganization(db.Organization{
		Identifier: "urn:oid:2.16.840.1.113883.2.4.6.1:00000000",
		Name:       "verpleeghuis De nootjes",
		PublicKey:  &pub,
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

