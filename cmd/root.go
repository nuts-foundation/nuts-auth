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

package cmd

import (
	"fmt"
	"github.com/nuts-foundation/nuts-auth/logging"
	"os"

	"github.com/nuts-foundation/nuts-auth/engine"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
)

var e = engine.NewAuthEngine()
var rootCmd = e.Cmd

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	c := core.NutsConfig()
	c.IgnoredPrefixes = append(c.IgnoredPrefixes, e.ConfigKey)
	c.RegisterFlags(rootCmd, e)
	if err := c.Load(rootCmd); err != nil {
		panic(err)
	}

	c.PrintConfig(logging.Log().Logger)

	if err := c.InjectIntoEngine(e); err != nil {
		panic(err)
	}

	// bootstrap registry and crypto for running nuts-auth as local server
	cr := crypto.CryptoInstance()
	cr.Config.Mode = core.ServerEngineMode
	if err := cr.Configure(); err != nil {
		panic(err)
	}

	r := registry.RegistryInstance()
	r.Config.Mode = core.ServerEngineMode
	r.Config.Datadir = "tmp"
	r.Config.SyncMode = "fs"
	if err := r.Configure(); err != nil {
		panic(err)
	}

	if err := e.Configure(); err != nil {
		panic(err)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
