package pkg

import (
	"os"
	"path"

	"github.com/nuts-foundation/nuts-auth/test"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/sirupsen/logrus"
)

func NewTestAuthInstance(testDirectory string) *Auth {
	config := DefaultAuthConfig()
	config.SkipAutoUpdateIrmaSchemas = true
	config.IrmaConfigPath = path.Join(testDirectory, "auth", "irma")
	config.ActingPartyCn = "CN=Awesomesoft"
	config.PublicUrl = "http://" + config.Address
	if err := os.MkdirAll(config.IrmaConfigPath, 0777); err != nil {
		logrus.Fatal(err)
	}
	if err := test.CopyDir("../testdata/irma", config.IrmaConfigPath); err != nil {
		logrus.Fatal(err)
	}
	config.IrmaSchemeManager = "irma-demo"
	newInstance := NewAuthInstance(config, crypto.NewTestCryptoInstance(testDirectory), registry.NewTestRegistryInstance(testDirectory))
	if err := newInstance.Configure(); err != nil {
		logrus.Fatal(err)
	}
	instance = newInstance
	return newInstance
}
