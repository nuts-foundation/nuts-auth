package pkg

import (
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/sirupsen/logrus"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
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
	if err := copyDir("../testdata/irma", config.IrmaConfigPath); err != nil {
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

func copyDir(src string, dst string) error {
	dir, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, os.ModePerm); err != nil {
		return err
	}
	for _, entry := range dir {
		sourceFile := filepath.Join(src, entry.Name())
		targetFile := filepath.Join(dst, entry.Name())
		if entry.IsDir() {
			err := copyDir(sourceFile, targetFile)
			if err != nil {
				return err
			}
			continue
		}
		if err := copyFile(sourceFile, targetFile); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(src string, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)

	return err
}