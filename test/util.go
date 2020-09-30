package test

import (
	"crypto/x509"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
	"time"

	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/test"
)

func RegisterVendor(t *testing.T, name string, crypto crypto.Client, registry registry.RegistryClient) {
	vendorCSRAsASN1, err := crypto.GenerateVendorCACSR(name)
	if err != nil {
		t.Fatal(err)
	}
	vendorCSR, err := x509.ParseCertificateRequest(vendorCSRAsASN1)
	vendorCSR.ExtraExtensions = vendorCSR.Extensions
	if err != nil {
		t.Fatal(err)
	}
	vendorPrivateKey, err := crypto.GetPrivateKey(types.KeyForEntity(types.LegalEntity{URI: core.NutsConfig().VendorID().String()}))
	if err != nil {
		t.Fatal(err)
	}
	cert := test.SignCertificateFromCSRWithKey(*vendorCSR, time.Now(), 365*3, nil, vendorPrivateKey)
	_, err = registry.RegisterVendor(cert)
	if err != nil {
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
