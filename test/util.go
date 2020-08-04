package test

import (
	"crypto/x509"
	crypto "github.com/nuts-foundation/nuts-crypto/pkg"
	"github.com/nuts-foundation/nuts-crypto/pkg/types"
	core "github.com/nuts-foundation/nuts-go-core"
	registry "github.com/nuts-foundation/nuts-registry/pkg"
	"github.com/nuts-foundation/nuts-registry/test"
	"testing"
	"time"
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
	cert := test.SignCertificateFromCSRWithKey(*vendorCSR, time.Now(), 365 * 3, nil, vendorPrivateKey)
	_, err = registry.RegisterVendor(cert)
	if err != nil {
		t.Fatal(err)
	}
}
