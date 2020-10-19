package test

import (
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
)

func RegisterVendor(t *testing.T, name string, crypto crypto.Client, registry registry.RegistryClient) {
	cert, err := crypto.SelfSignVendorCACertificate(name)
	if err != nil {
		t.Fatal(err)
	}
	_, err = registry.RegisterVendor(cert)
	if err != nil {
		t.Fatal(err)
	}
	if err = crypto.TrustStore().AddCertificate(cert); err != nil {
		t.Fatal(err)
	}
}

func CopyDir(src string, dst string) error {
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
			err := CopyDir(sourceFile, targetFile)
			if err != nil {
				return err
			}
			continue
		}
		if err := CopyFile(sourceFile, targetFile); err != nil {
			return err
		}
	}
	return nil
}

func CopyFile(src string, dst string) error {
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
