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

package pkg

import (
	"os"
	"path"
	"testing"

	test2 "github.com/nuts-foundation/nuts-auth/test"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	core "github.com/nuts-foundation/nuts-go-core"
	testIo "github.com/nuts-foundation/nuts-go-test/io"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/test"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var OrganizationID = test.OrganizationID("00000001")

const VendorID = "urn:oid:1.3.6.1.4.1.54851.4:vendorId"

// TestInstance returns an Auth instance with mock crypto and registry
func TestInstance(t *testing.T, cfg AuthConfig) *Auth {
	testDirectory := testIo.TestDirectory(t)
	_ = os.Setenv("NUTS_IDENTITY", VendorID)
	_ = core.NutsConfig().Load(&cobra.Command{})

	return NewAuthInstance(cfg, crypto.NewTestCryptoInstance(testDirectory), registry.NewTestRegistryInstance(testDirectory))
}

// NewTestAuthInstance returns a fully configured Auth instance
func NewTestAuthInstance(t *testing.T) *Auth {
	testDirectory := testIo.TestDirectory(t)
	config := DefaultAuthConfig()
	config.SkipAutoUpdateIrmaSchemas = true
	config.IrmaConfigPath = path.Join(testDirectory, "auth", "irma")
	config.ActingPartyCn = "CN=Awesomesoft"
	config.PublicUrl = "http://" + config.Address
	if err := os.MkdirAll(config.IrmaConfigPath, 0777); err != nil {
		logrus.Fatal(err)
	}
	if err := test2.CopyDir("../testdata/irma", config.IrmaConfigPath); err != nil {
		logrus.Fatal(err)
	}
	config.IrmaSchemeManager = "irma-demo"
	newInstance := NewAuthInstance(config, crypto.NewTestCryptoInstance(testDirectory), registry.NewTestRegistryInstance(testDirectory))
	if err := newInstance.Configure(); err != nil {
		logrus.Fatal(err)
	}

	return newInstance
}

// RegisterTestDependencies registers minimal dependencies
func RegisterTestDependencies(t *testing.T) {
	// This makes sure instances of Auth use test instances of Crypto and Registry which write their data to a temp dir
	testDirectory := testIo.TestDirectory(t)
	_ = os.Setenv("NUTS_IDENTITY", VendorID)
	_ = core.NutsConfig().Load(&cobra.Command{})
	crypto.NewTestCryptoInstance(testDirectory)
	registry.NewTestRegistryInstance(testDirectory)
}
